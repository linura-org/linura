#!/usr/bin/env python3
"""Check mandatory native CI gates and critical specialized qualification routing."""

from __future__ import annotations

import argparse
import ast
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tomllib
import textwrap

ROOT = Path(__file__).resolve().parents[1]
MANDATORY = {
    "canonical-check": ".github/workflows/ci.yml",
    "dependency-audit": ".github/workflows/security.yml",
    "analyze": ".github/workflows/codeql.yml",
}
# Review this minimum map when a new subsystem or qualification lane is added.
# It deliberately does not assert that every possible change is qualified.
SPECIALIZED = {
    "codex": (
        ".github/workflows/codex-environment.yml",
        (
            "AGENTS.md",
            "docs/codex-development.md",
            "scripts/setup_codex_environment.sh",
            "scripts/preflight_codex_environment.sh",
            "scripts/maintain_codex_environment.sh",
            "scripts/run_codex.sh",
            "scripts/lib/codex_source_state.sh",
            "scripts/lib/bootstrap_rustup.sh",
            "tools/codex/doctor.py",
            "tools/codex/versions.env",
            "tools/check_toolchain_env.py",
            "tests/tooling/test_toolchain_env.py",
            "tests/tooling/test_codex_readiness.py",
            "bindings/python/build-requirements.lock",
            "rust-toolchain.toml",
            "Cargo.lock",
            "Cargo.toml",
            "tools/check_validation_gates.py",
            "tests/tooling/test_validation_gates.py",
        ),
    ),
    "vm": (
        ".github/workflows/vm-acceptance.yml",
        (
            "tools/vm.py",
            "tools/qualification_guest_identity.py",
            "tests/acceptance/008-control1-plan-preview.json",
            "crates/linura-linux-observation/Cargo.toml",
        ),
    ),
    "v04-durability": (
        ".github/workflows/v04-durability-vm.yml",
        (
            "crates/linura-transaction/Cargo.toml",
            "crates/linura-persistence-sqlite/Cargo.toml",
            "tools/vm.py",
            "tools/qualification_guest_identity.py",
        ),
    ),
    "v04-enospc": (
        ".github/workflows/v04-enospc-recovery-vm.yml",
        (
            "crates/linura-transaction/Cargo.toml",
            "crates/linura-persistence-sqlite/Cargo.toml",
            "tools/vm.py",
            "tools/qualification_guest_identity.py",
        ),
    ),
    "v05": (
        ".github/workflows/v05-executor-verifier-vm.yml",
        (
            "executors/linura-executor-systemd/Cargo.toml",
            "verifiers/linura-verifier-systemd/Cargo.toml",
            "crates/linura-linux-observation/Cargo.toml",
            "tools/qualification_guest_identity.py",
        ),
    ),
    "v06": (
        ".github/workflows/v06-managed-lifecycle-vm.yml",
        (
            "crates/linura-lifecycle/Cargo.toml",
            "crates/linura-transaction/Cargo.toml",
            "executors/linura-executor-systemd/Cargo.toml",
            "tools/qualification_guest_identity.py",
        ),
    ),
    "v07": (
        ".github/workflows/v07-library-qualification.yml",
        (
            "crates/linura-library/Cargo.toml",
            "crates/linura-intent/Cargo.toml",
            "scripts/check_repository.py",
        ),
    ),
    "v08": (
        ".github/workflows/v08-agent-qualification.yml",
        (
            "crates/linura-agent-runtime/Cargo.toml",
            "crates/linura-control/Cargo.toml",
            "scripts/check_repository.py",
        ),
    ),
    "v09": (
        ".github/workflows/v09-qualification.yml",
        (
            "tools/v09_qualification_scope.py",
            "tests/tooling/test_v09_qualification_scope.py",
            "tests/acceptance/002-firstboot-offline.json",
            "contracts/v09-qualification-routing.toml",
            "tools/image.py",
            "contracts/operation-semantics.toml",
            "tools/check_validation_gates.py",
            "tests/tooling/test_validation_gates.py",
            "crates/linura-control/Cargo.toml",
        ),
    ),
    "v010": (
        ".github/workflows/v010-qualification.yml",
        (
            "apps/linura-shell/bridge/CMakeLists.txt",
            "contracts/v010-workstation-slices.toml",
            "qualification/v010/shell-runtime/run-shell-runtime.sh",
            "qualification/v010/shell-runtime/native-keyboard.c",
            "tools/verify_tray_keyboard.py",
            "tests/tooling/test_native_keyboard.py",
            ".github/workflows/v010-shell-runtime-qualification.yml",
            "tools/qualification_guest_identity.py",
            "tools/development_workspace.py",
            "tools/development_storage.py",
            "scripts/prepare_qualification_storage.sh",
            "tools/codex/doctor.py",
            "tests/tooling/test_development_workspace.py",
            "tests/tooling/test_development_storage.py",
        ),
    ),
    "evidence-publication": (
        ".github/workflows/evidence-publication-checks.yml",
        (
            ".github/workflows/publish-qualification-evidence.yml",
            "contracts/evidence-publication.toml",
            "tools/evidence_publication.py",
            "tests/tooling/test_evidence_publication.py",
            "tools/check_validation_gates.py",
            "tests/tooling/test_validation_gates.py",
            "docs/qualification/evidence-publication.md",
            "docs/qualification/evidence-publication-threat-model.md",
            "docs/security-model.md",
            "docs/adr/0034-private-qualification-evidence-publication.md",
            "docs/adr/0035-isolate-media-admission-from-r2-credentials.md",
            "docs/adr/README.md",
        ),
    ),
}

# These independent qualification jobs are inherited release requirements;
# preserving PR triggers alone cannot prevent a release-proof bypass.
V09_ROUTING_GUARD_EXACT = (
    ".github/workflows/v09-qualification.yml",
    "contracts/v09-qualification-routing.toml",
    "tools/v09_qualification_scope.py",
    "tests/tooling/test_v09_qualification_scope.py",
    "tools/check_validation_gates.py",
    "tests/tooling/test_validation_gates.py",
)

# Reviewed exact-path minimum for the v0.9 full-qualification lane.
# Like the required prefix set below, this is intentionally independent of
# the TOML allowlist: deleting a protected route from the contract must not
# make the validator forget that the route is mandatory.
V09_REQUIRED_FULL_EXACT = (
    "tools/development_workspace.py",
    "tools/development_storage.py",
    "scripts/prepare_qualification_storage.sh",
    "tools/codex/doctor.py",
    "tests/tooling/test_development_workspace.py",
    "tests/tooling/test_development_storage.py",
    ".github/workflows/v09-qualification.yml",
    ".github/workflows/v09-adversarial-security.yml",
    ".github/workflows/vm-acceptance.yml",
    ".github/workflows/trusted-release-proof.yml",
    ".github/actions/qualification-envelope/action.yml",
    "contracts/qualification-execution-envelopes.toml",
    "tools/qualification_envelope.py",
    "tools/qualification_guest_identity.py",
    "tests/tooling/test_qualification_envelope.py",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config",
    ".cargo/config.toml",
    "packaging/wireplumber/linura-session-audio.lua",
    "rust-toolchain.toml",
    "tools/codex/versions.env",
    "tools/vm.py",
    "tools/acceptance.py",
    "scripts/qualification/v09-adversarial-guest.sh",
    "tools/image.py",
    "tools/check_validation_gates.py",
    "tests/tooling/test_validation_gates.py",
    "tools/v09_qualification_scope.py",
    "tests/tooling/test_v09_qualification_scope.py",
    "contracts/components.toml",
    "contracts/operation-semantics.toml",
    "contracts/stability.toml",
    "hardware/support-matrix.json",
    "contracts/v09-qualification-routing.toml",
    "tests/tooling/test_v09_recovery_qualification.py",
    "tests/tooling/test_v09_bootstrap_provisioning_contract.py",
    "tests/tooling/test_v09_adversarial_fast_forward_contract.py",
    "tests/tooling/test_v09_adversarial_transport_contract.py",
    "tests/tooling/test_v09_adversarial_sharding_contract.py",
    "packaging/arch/hooks/95-linura-update-guard.hook",
)

V09_REQUIRED_FULL_PREFIXES = (
    "apps/linura-firstboot/",
    "apps/linura-authorityd/",
    "apps/linura-update-guard/",
    "apps/linurad/",
    "apps/linuractl/",
    "crates/linura-sdk/",
    "crates/linura-bootstrap/",
    "crates/linura-migrations/",
    "crates/linura-update/",
    "crates/linura-control/",
    "crates/linura-core/",
    "crates/linura-agent-runtime/",
    "crates/linura-dbus/",
    "crates/linura-library/",
    "crates/linura-lifecycle/",
    "crates/linura-provider-sdk/",
    "crates/linura-policy/",
    "crates/linura-planner/",
    "crates/linura-transaction/",
    "crates/linura-persistence-sqlite/",
    "crates/linura-graph/",
    "crates/linura-intent/",
    "crates/linura-provenance/",
    "crates/linura-protocol/",
    "crates/linura-capability-sdk/",
    "crates/linura-hardware/",
    "crates/linura-linux-observation/",
    "crates/linura-observation/",
    "crates/linura-observation-control/",
    "interfaces/dbus/",
    "executors/",
    "verifiers/",
    "tests/acceptance/",
    "migrations/",
)

V09_AUTHORITY_NEGATIVE_COMMAND = (
    "if output=$(LINURA_AUTHORITY_STATE_DIR=/dev/null/linura-authority-qualification "
    "/usr/local/bin/linura-authorityd 2>&1); then "
    "printf '%s\\n' 'authority daemon unexpectedly accepted invalid state directory' >&2; "
    "exit 1; fi; case \"$output\" in *'linura-authorityd failed closed:'*) "
    "printf '%s\\n' 'authority daemon rejected invalid state directory' ;; "
    "*) printf '%s\\n' \"$output\" >&2; exit 1 ;; esac"
)


RELEASE_INHERITED = {
    "observation-acceptance": ".github/workflows/vm-acceptance.yml",
    "plan-preview-acceptance": ".github/workflows/vm-acceptance.yml",
    "durability-qualification": ".github/workflows/v04-durability-vm.yml",
    "enospc-qualification": ".github/workflows/v04-enospc-recovery-vm.yml",
    "executor-verifier-qualification": ".github/workflows/v05-executor-verifier-vm.yml",
    "managed-lifecycle-qualification": ".github/workflows/v06-managed-lifecycle-vm.yml",
    "library-qualification": ".github/workflows/v07-library-qualification.yml",
    "agent-qualification": ".github/workflows/v08-agent-qualification.yml",
    "firstboot-qualification": ".github/workflows/v09-qualification.yml",
}


# Pin the executable canonical check body; strings in Rust comments are not evidence.
XTASK_CHECK_BODY = '    run("cargo", &["fmt", "--all", "--check"])?;\n    run("python3", &["tools/check_source_formatting.py"])?;\n    verify_ruff_version()?;\n    run("ruff", &["check", "."])?;\n    run("ruff", &["format", "--check", "."])?;\n    run(\n        "cargo",\n        &[\n            "clippy",\n            "--workspace",\n            "--all-targets",\n            "--all-features",\n            "--locked",\n            "--",\n            "-D",\n            "warnings",\n        ],\n    )?;\n    run(\n        "cargo",\n        &["test", "--workspace", "--all-features", "--locked"],\n    )?;\n    run("python3", &["scripts/check_repository.py"])?;\n    component_maturity()?;\n    authority_foundation()?;\n    run("python3", &["scripts/validate_assets.py"])?;\n    desktop_identity()?;\n    release_contracts()?;\n    run("python3", &["tools/run_tooling_tests.py"])?;\n    Ok(())\n'
REVIEWED_TOOLING_RUNNER_SHA256 = (
    "914e7291144319c2c6c5c525d0d5461ed326f38ddd30b2c9f23c14b5cc76a366"
)

PYPI_VERIFICATION_COMMANDS = (
    "set -euo pipefail",
    "PYTHONPATH=bindings/python/src python3 -m unittest discover \\",
    "-s bindings/python/tests -p 'test_*.py'",
    'dist_dir="$RUNNER_TEMP/linura-python-dist"',
    'install_dir="$RUNNER_TEMP/linura-python-install"',
    'rm -rf "$dist_dir" "$install_dir"',
    'mkdir -p "$dist_dir" "$install_dir"',
    "python3 -m pip wheel \\",
    "--disable-pip-version-check \\",
    "--no-deps \\",
    '--wheel-dir "$dist_dir" \\',
    "./bindings/python",
    "python3 -m pip install \\",
    "--disable-pip-version-check \\",
    "--no-deps \\",
    '--target "$install_dir" \\',
    '"$dist_dir"/linura-*.whl',
    "PYTHONPATH=\"$install_dir\" python3 - <<'PY'",
    "import linura",
    'assert linura.__version__ == "0.0.2"',
    'assert linura.CONTROL1_SERVICE == "org.linura.Control1"',
    'assert linura.find_installation(path="") is None',
    "PY",
)


WORKFLOW_CONTROL_KEYS = frozenset(
    (
        "if",
        "needs",
        "continue-on-error",
        "defaults",
        "on",
        "pull_request",
        "push",
        "branches",
        "branches-ignore",
        "types",
        "paths",
        "paths-ignore",
        "schedule",
        "cron",
        "shell",
        "uses",
        "with",
        "env",
    )
)

_WORKFLOW_CONTROL_SPACING = re.compile(
    r"^([ \t]*(?:-[ \t]+)?)((?:"
    + "|".join(
        re.escape(key) for key in sorted(WORKFLOW_CONTROL_KEYS, key=len, reverse=True)
    )
    + r"))[ \t]+:"
)


def normalize_workflow_keys(source: str) -> str:
    """Canonicalize reviewed YAML control keys without touching literal shell code.

    This static gate intentionally accepts block mappings for its protected
    control surfaces. Decode JSON-compatible quoted control keys before
    auditing. Reject other quoted keys, unsupported YAML escapes, explicit
    mapping keys, merges and standalone flow mappings rather than silently
    approving syntax the line-oriented audit does not understand.
    """
    result = []
    scalar_indent = None
    for line in source.splitlines(keepends=True):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if scalar_indent is not None:
            if not stripped or indent > scalar_indent:
                result.append(line)
                continue
            scalar_indent = None
        if not stripped or stripped.startswith("#"):
            result.append(line)
            continue
        # Audit action-value syntax before treating YAML block scalars as
        # opaque. Block, tagged, anchored, aliased or missing uses values can
        # conceal a later checkout from the line-oriented source audit.
        action_scalar = re.match(
            r"""^[ \t]*(?:-[ \t]+)?(uses|"(?:\\.|[^"\\])*"|'(?:''|[^'])*')[ \t]*:[ \t]*(.*)$""",
            line.rstrip("\r\n"),
        )
        if action_scalar:
            key = action_scalar.group(1)
            if key.startswith('"'):
                try:
                    key = json.loads(key)
                except (ValueError, UnicodeError) as exc:
                    raise ValueError("unsupported action key encoding") from exc
            elif key.startswith("'"):
                key = key[1:-1].replace("''", "'")
            if key == "uses":
                value = action_scalar.group(2).strip()
                if not value or value[0] in "|>!&*{[":
                    raise ValueError("noncanonical action references are not audited")
                # YAML decodes escapes in quoted action scalars. Canonicalize
                # the decoded value *before* counting all checkout occurrences;
                # otherwise an escaped later checkout can replace source.
                if value.startswith(("'", '"')):
                    scalar = re.fullmatch(
                        r"""("(?:\\.|[^"\\])*"|'(?:''|[^'])*')([ \t]*(?:#.*)?)?""",
                        value,
                    )
                    if scalar is None:
                        raise ValueError("unsupported quoted action reference")
                    token = scalar.group(1)
                    try:
                        decoded = (
                            json.loads(token)
                            if token[0] == '"'
                            else token[1:-1].replace("''", "'")
                        )
                    except (ValueError, UnicodeError) as exc:
                        raise ValueError("unsupported action reference escape") from exc
                    if re.fullmatch(r"[A-Za-z0-9_./@:-]+", decoded) is None:
                        raise ValueError("noncanonical decoded action reference")
                    line = (
                        line[: action_scalar.start(2)]
                        + decoded
                        + (scalar.group(2) or "")
                        + (
                            "\r\n"
                            if line.endswith("\r\n")
                            else "\n"
                            if line.endswith("\n")
                            else ""
                        )
                    )
        if re.search(r":[ \t]*[|>][-+]?[0-9]?[ \t]*(?:#.*)?$", line.rstrip("\r\n")):
            scalar_indent = indent
            result.append(line)
            continue
        if re.match(r"^[ \t]*(?:\?[ \t]+|<<[ \t]*:|\{|(?:-[ \t]+)?[&*!])", line):
            raise ValueError(
                "explicit, merged, anchored, tagged or standalone flow mapping is not audited"
            )
        quoted = re.match(r"""^([ \t]*(?:-[ \t]+)?)(["'])(.*?)\2[ \t]*:""", line)
        if quoted:
            quote, raw = quoted.group(2), quoted.group(3)
            try:
                decoded = (
                    json.loads('"' + raw + '"')
                    if quote == '"'
                    else raw.replace("''", "'")
                )
            except (ValueError, UnicodeError) as exc:
                raise ValueError("unsupported quoted mapping key encoding") from exc
            if decoded not in WORKFLOW_CONTROL_KEYS:
                raise ValueError("noncanonical quoted mapping key")
            line = quoted.group(1) + decoded + ":" + line[quoted.end() :]
        elif re.match(r"^[ \t]*(?:-[ \t]+)?[\"']", line):
            # A quoted sequence value on one line (e.g. a path glob) is safe.
            # Unterminated quoted mapping keys can span lines and evade audit.
            if not re.fullmatch(
                r"[ \t]*-[ \t]+([\"'])(?:.*)\1[ \t]*(?:#.*)?\r?\n?", line
            ):
                raise ValueError("noncanonical or multiline quoted mapping key")
        else:
            # YAML permits spaces before a plain mapping key's colon. The
            # inspected job/step and checkout guards require canonical keys.
            # Normalize only audited keys, never values or literal run blocks.
            line = _WORKFLOW_CONTROL_SPACING.sub(r"\1\2:", line, count=1)
        result.append(line)
    return "".join(result)


def section(text: str, heading: str, indent: int = 0) -> str | None:
    lines = text.splitlines(keepends=True)
    prefix = " " * indent
    for pos, line in enumerate(lines):
        if (
            line.strip() != heading + ":"
            or not line.startswith(prefix)
            or line.startswith(prefix + " ")
        ):
            continue
        contents = []
        for next_line in lines[pos + 1 :]:
            if (
                next_line.strip()
                and len(next_line) - len(next_line.lstrip(" ")) <= indent
            ):
                break
            contents.append(next_line)
        return "".join(contents)
    return None


def workflow_step(job_body: str, job_indent: int, key: str, value: str) -> str | None:
    """Locate an actual step under the direct steps mapping, not shell text."""
    steps = section(job_body, "steps", job_indent)
    if steps is None:
        return None
    list_indent = job_indent + 2
    entries = list(
        re.finditer(
            r"(?m)^ {" + str(list_indent) + r"}- (?:name|uses|run):[^\n]*$", steps
        )
    )
    for index, entry in enumerate(entries):
        first = entry.group(0).strip()[2:]
        if first.startswith(key + ": ") and first[len(key) + 2 :].startswith(value):
            end = entries[index + 1].start() if index + 1 < len(entries) else len(steps)
            return steps[entry.start() : end]
    return None


def step_is_unconditional(
    step: str | None,
    job_indent: int,
    *,
    allow_reviewed_shell: bool = False,
) -> bool:
    """A mandatory step must not be skipped or turn a failure into success.

    The sole explicit-shell exception is for the publisher's first executable
    step. Its precise trusted shell is independently pinned by byte-for-byte
    comparison to reviewed_tests. Every other caller still rejects shell.
    """
    if step is None:
        return False
    prop_indent = job_indent + 4
    guards = (
        "if|continue-on-error" if allow_reviewed_shell else "if|continue-on-error|shell"
    )
    return (
        re.search(r"(?m)^ {" + str(prop_indent) + r"}(?:" + guards + r"):", step)
        is None
    )


def protected_step_guards(
    job_body: str,
    job_indent: int,
    reviewed: dict[str, str],
) -> bool:
    """Reject step guards not expressly reviewed for the qualification lane.

    The line-oriented step reader handles canonical block-style entries only;
    run: | source is never interpreted as a workflow mapping.
    """
    steps = section(job_body, "steps", job_indent)
    if steps is None:
        return True  # A reusable-workflow caller has no local executable steps.
    list_indent = job_indent + 2
    headers = list(
        re.finditer(
            r"(?m)^ {" + str(list_indent) + r"}-[ \t]+[^\r\n]+$",
            steps,
        )
    )
    entries = list(
        re.finditer(
            r"(?m)^ {" + str(list_indent) + r"}- (?:name|uses|run):[^\r\n]*$",
            steps,
        )
    )
    if not headers or len(headers) != len(entries):
        return False
    for pos, entry in enumerate(entries):
        end = entries[pos + 1].start() if pos + 1 < len(entries) else len(steps)
        step = steps[entry.start() : end]
        heading = entry.group(0).strip()[2:]
        label = heading[len("name:") :].strip() if heading.startswith("name:") else ""
        prop_indent = job_indent + 4
        conditions = re.findall(
            r"(?m)^ {" + str(prop_indent) + r"}if:[ \t]*([^\r\n]*)$",
            step,
        )
        if (
            len(conditions) > 1
            or re.search(r"(?m)^ {" + str(prop_indent) + r"}continue-on-error:", step)
            is not None
        ):
            return False
        if conditions and (not label or conditions[0].strip() != reviewed.get(label)):
            return False
    return True


def checkout_is_triggering_revision(job_body: str, job_indent: int) -> bool:
    """Require one unconditional immutable checkout with no source override."""
    # Fail closed on flow-style step mappings in protected jobs. Otherwise
    # a second checkout written as "- {uses: ..., with: {ref: main}}"
    # escapes the block-style step reader and replaces the verified source.
    # These critical jobs intentionally require block-style YAML steps.
    steps = section(job_body, "steps", job_indent)
    if steps is None or re.search(
        r"(?m)^ {" + str(job_indent + 2) + r"}-[ \t]*\{", steps
    ):
        return False
    checkout = workflow_step(job_body, job_indent, "uses", "actions/checkout@")
    # GitHub accepts quoted action identifiers and named steps whose "uses"
    # property is on a subsequent line. All of them count as checkouts:
    # a later checkout can silently replace the triggering source.
    occurrences = re.findall(
        r"""(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?actions/checkout@""",
        job_body,
    )
    if (
        len(occurrences) != 1
        or not step_is_unconditional(checkout, job_indent)
        or re.search(
            r"(?m)^ {"
            + str(job_indent + 2)
            + r"}- uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
            checkout or "",
        )
        is None
    ):
        return False
    # Inline YAML mappings also count as with options; only the audited
    # fetch-depth: 0 option is permitted, never ref, repository, etc.
    with_lines = re.findall(
        r"(?m)^ {" + str(job_indent + 4) + r"}with:(.*)$", checkout or ""
    )
    if not with_lines:
        return True
    options = section(checkout or "", "with", job_indent + 4)
    return (
        len(with_lines) == 1
        and not with_lines[0].strip()
        and options is not None
        and re.fullmatch(r"\s*fetch-depth: 0\s*", options) is not None
    )


def specialized_exact_source_checkout(
    job_body: str,
    job_indent: int,
    expected_ref: str = "ref: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}",
) -> bool:
    """Require one unconditional audited checkout bound to SOURCE_SHA."""
    steps = section(job_body, "steps", job_indent)
    if steps is None or re.search(
        r"(?m)^ {" + str(job_indent + 2) + r"}-[ \t]*\{", steps
    ):
        return False
    checkout = workflow_step(job_body, job_indent, "uses", "actions/checkout@")
    occurrences = re.findall(
        r"""(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?actions/checkout@""",
        job_body,
    )
    if len(occurrences) != 1 or not step_is_unconditional(checkout, job_indent):
        return False
    action = (
        r"(?m)^ {"
        + str(job_indent + 2)
        + r"}- uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$"
    )
    if re.search(action, checkout or "") is None:
        return False
    options = section(checkout or "", "with", job_indent + 4)
    if options is None:
        return False
    actual = tuple(line.strip() for line in options.splitlines() if line.strip())
    expected = (
        "persist-credentials: false",
        "fetch-depth: 0",
        expected_ref,
    )
    return actual == expected


def executable_run_block(step: str | None, job_indent: int) -> tuple[str, ...]:
    """Preserve meaningful indentation in a reviewed multiline shell block."""
    if step is None:
        return ()
    lines = step.splitlines()
    marker = " " * (job_indent + 4) + "run: |"
    if marker not in lines:
        return ()
    prefix = " " * (job_indent + 6)
    code = [line for line in lines[lines.index(marker) + 1 :] if line.strip()]
    if any(not line.startswith(prefix) for line in code):
        return ()
    return tuple(line[len(prefix) :] for line in code)


@lru_cache(maxsize=1024)
def _compiled_path_pattern(pattern: str) -> re.Pattern[str]:
    tokens = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            tokens.append(".*")
            i += 2
        elif pattern[i] == "*":
            tokens.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            tokens.append("[^/]")
            i += 1
        else:
            tokens.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(tokens))


def path_matches(path: str, pattern: str) -> bool:
    return _compiled_path_pattern(pattern).fullmatch(path) is not None


def path_selected(path: str, patterns: list[str]) -> bool:
    """Model GitHub's ordered PR path filters, including ! exclusions."""
    selected = False
    for pattern in patterns:
        excluded = pattern.startswith("!")
        glob = pattern[1:] if excluded else pattern
        if glob and path_matches(path, glob):
            selected = not excluded
    return selected


# Exclude only known guidance files from expensive machine-only qualification.
# Broad docs exclusions are unsafe: implementation and contract files must
# remain eligible even when an unrelated guidance file changes in the same PR.
# Required entry jobs must run whenever the specialty path filter selects them.
# v0.9 deliberately has conditional downstream full/regression jobs; scope
# and contract choose the correct lane and are always required.
SPECIALIZED_REQUIRED_JOBS = {
    "codex": ("fresh-environment",),
    "vm": ("vm",),
    "v04-durability": ("durability",),
    "v04-enospc": ("enospc",),
    "v05": ("qualification",),
    "v06": ("qualification",),
    "v07": ("qualification",),
    "v08": ("qualification",),
    "v09": ("scope", "contract"),
    "v010": ("contract", "shell-runtime"),
    "evidence-publication": ("verify",),
}

# Exact allowed step conditions, bound to reviewed step identities.
# Qualification and exact-source steps otherwise execute unconditionally.
REVIEWED_STEP_CONDITIONS = {
    ("vm", "vm"): {
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Collect VM diagnostics": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified VM diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v04-durability", "durability"): {
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified v0.4 durability diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v04-enospc", "enospc"): {
        "Record exact-source ENOSPC evidence": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified ENOSPC diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v05", "qualification"): {
        "Collect executor hardening evidence": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Collect QEMU diagnostics": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified v05-executor-verifier diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v06", "qualification"): {
        "Collect authority and executor hardening evidence": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Collect QEMU diagnostics": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified v06-managed-lifecycle diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v07", "qualification"): {
        "Upload unqualified v0.7 diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v08", "qualification"): {
        "Upload unqualified v0.8 diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
    ("v09", "contract"): {
        "Build exact-source adversarial qualification binaries": "needs.scope.outputs.full_qualification == 'true'",
        "Upload exact-source adversarial qualification binaries": "needs.scope.outputs.full_qualification == 'true'",
    },
    ("v010-reusable", "substrate"): {
        "Stage restored prepared substrate into private run": "steps.prepared-substrate.outputs.cache-hit == 'true'",
        "Stage verified prepared substrate in stable prerequisite cache": "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Install disposable substrate builder dependencies": "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Restore official Arch base-image cache": "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Download and verify official Arch base image": "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Build sanitized prepared runtime substrate": "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Save prepared runtime substrate": "steps.prepared-substrate.outputs.cache-hit != 'true'",
    },
    ("v010-reusable", "runtime"): {
        "Stop disposable guest": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Collect QEMU diagnostics": "${{ always() && steps.toolchain_data.outcome == 'success' }}",
        "Upload unqualified v0.10 shell diagnostics": "${{ failure() && steps.toolchain_data.outcome == 'success' }}",
    },
}


GUIDANCE_EXCLUSIONS = {
    "v010": ("apps/linura-shell/AGENTS.md", "apps/linura-shell/README.md"),
}


CODEX_REQUIRED_STEPS = (
    (
        "Prepare isolated environment",
        ('task_home="$RUNNER_TEMP/linura-codex-home"', '"$GITHUB_ENV"'),
    ),
    (
        "Bootstrap from host primitives",
        ("run: PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings",),
    ),
    (
        "Inject stale bindings distribution before maintenance",
        (
            "linura-contaminant-0.0.1.dist-info",
            "if python3 tools/codex/doctor.py --profile bindings --json",
            "exit 1",
        ),
    ),
    (
        "Resume cached environment at selected checkout",
        (
            "run: PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings",
        ),
    ),
    (
        "Verify maintenance removed contaminated distributions",
        (
            "python3 tools/codex/doctor.py --profile bindings --json",
            '"linura-contaminant"',
        ),
    ),
    (
        "Verify from a separate task process",
        (
            "scripts/preflight_codex_environment.sh --full",
            "--no-index --no-deps --no-build-isolation",
        ),
    ),
)


CODEX_CONTAMINATION_COMMANDS = (
    "set -euo pipefail",
    "\"$HOME/.local/linura-tools/python/bin/python3\" - <<'PY'",
    "import pathlib",
    "import sysconfig",
    'site = pathlib.Path(sysconfig.get_paths()["purelib"])',
    'stale = site / "linura-contaminant-0.0.1.dist-info"',
    "stale.mkdir()",
    '(stale / "METADATA").write_text(',
    '    "Metadata-Version: 2.1\\nName: linura-contaminant\\nVersion: 0.0.1\\n"',
    ")",
    "PY",
    'if python3 tools/codex/doctor.py --profile bindings --json > "$RUNNER_TEMP/contaminated-bindings.json"; then',
    '  echo "doctor accepted an undeclared cached distribution" >&2',
    "  exit 1",
    "fi",
)


# Review the complete executable content, not just tokens that could occur
# after an early exit or in a shell comment. The six required steps are all
# covered: these four plus the injection and task-time verification below.
CODEX_OTHER_EXECUTION_CONTRACTS = {
    "Prepare isolated environment": (
        "set -euo pipefail",
        'task_home="$RUNNER_TEMP/linura-codex-home"',
        'mkdir -p "$task_home"',
        "{",
        "  printf 'HOME=%s\\n' \"$task_home\"",
        "  printf 'CARGO_HOME=%s/.cargo\\n' \"$task_home\"",
        "  printf 'RUSTUP_HOME=%s/.rustup\\n' \"$task_home\"",
        '} >> "$GITHUB_ENV"',
    ),
    "Bootstrap from host primitives": "PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings",
    "Resume cached environment at selected checkout": "PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings",
    "Verify maintenance removed contaminated distributions": (
        "set -euo pipefail",
        'python3 tools/codex/doctor.py --profile bindings --json > "$RUNNER_TEMP/clean-bindings.json"',
        "\"$HOME/.local/linura-tools/python/bin/python3\" - <<'PY'",
        "import importlib.metadata as metadata",
        'assert all(dist.metadata["Name"] != "linura-contaminant" for dist in metadata.distributions())',
        "PY",
    ),
}


def v09_lane_job_graph_connected(workflow: str) -> bool:
    """Pin full/regression jobs to the reviewed classifier output and dependency graph."""
    jobs = section(workflow, "jobs") or ""

    expected = {
        "scope": {
            "needs": None,
            "if": None,
            "uses": None,
        },
        "contract": {
            "needs": "scope",
            "if": None,
            "uses": None,
        },
        "offline-reference": {
            "needs": "[scope, contract]",
            "if": "needs.scope.outputs.full_qualification == 'true'",
            "uses": "./.github/workflows/vm-acceptance.yml",
        },
        "adversarial-security": {
            "needs": "[scope, contract]",
            "if": "needs.scope.outputs.full_qualification == 'true'",
            "uses": "./.github/workflows/v09-adversarial-security.yml",
        },
        "regression-proof": {
            "needs": "[scope, contract]",
            "if": "needs.scope.outputs.full_qualification != 'true'",
            "uses": None,
        },
        "qualification-proof": {
            "needs": "[scope, contract, offline-reference, adversarial-security]",
            "if": "needs.scope.outputs.full_qualification == 'true'",
            "uses": None,
        },
    }
    for job_name, controls in expected.items():
        body = section(jobs, job_name, 2)
        if body is None:
            return False
        needs = re.findall(r"(?m)^    needs:[ \t]*(.+?)[ \t]*$", body)
        expected_needs = [] if controls["needs"] is None else [controls["needs"]]
        if needs != expected_needs:
            return False
        guards = re.findall(r"(?m)^    if:[ \t]*(.+?)[ \t]*$", body)
        expected_guard = [] if controls["if"] is None else [controls["if"]]
        if guards != expected_guard:
            return False
        uses = re.findall(r"(?m)^    uses:[ \t]*(.+?)[ \t]*$", body)
        expected_uses = [] if controls["uses"] is None else [controls["uses"]]
        if uses != expected_uses:
            return False
        if re.search(r"(?m)^    continue-on-error:", body) is not None:
            return False
    return True


def v09_classifier_connected(workflow: str) -> bool:
    """Fail closed unless the live router matches the reviewed executable AST.

    This protects changed-path provenance, canonical contract loading,
    classification and exact GITHUB_OUTPUT publication as one data flow.
    Refactors require changing the reviewed reference and adversarial tests.
    """
    jobs = section(workflow, "jobs") or ""
    scope = section(jobs, "scope", 2) or ""
    outputs = section(scope, "outputs", 4)
    output_entries = [
        line.strip()
        for line in (outputs or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if output_entries != [
        "full_qualification: ${{ steps.route.outputs.full_qualification }}"
    ]:
        return False
    route = workflow_step(scope, 4, "name", "Resolve exact-source qualification lane")
    if (
        not step_is_unconditional(route, 4)
        or re.findall(r"(?m)^        id:[ \t]*(\S+)[ \t]*$", route or "") != ["route"]
        or len(re.findall(r"(?m)^        id:[ \t]*route[ \t]*$", scope)) != 1
    ):
        return False
    marker = "        run: |"
    lines = (route or "").splitlines()
    if lines.count(marker) != 1:
        return False
    body = lines[lines.index(marker) + 1 :]
    while body and not body[-1].strip():
        body.pop()
    if not body or any(
        line.strip() and not line.startswith("          ") for line in body
    ):
        return False
    run = "\n".join(line[10:] if line else "" for line in body) + "\n"
    heredoc = 'python3 - "$changed" "$GITHUB_OUTPUT" <<\'PY\'\n'
    parts = run.split(heredoc)
    if len(parts) != 2 or not parts[1].endswith("PY\n"):
        return False
    shell = parts[0]
    source = parts[1][: -len("PY\n")]
    executable_shell = tuple(
        line.strip()
        for line in shell.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected_shell = (
        "set -euo pipefail",
        'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
        'if [[ "$GITHUB_EVENT_NAME" != "pull_request" ]]; then',
        "printf 'full_qualification=true\\n' >> \"$GITHUB_OUTPUT\"",
        "exit 0",
        "fi",
        '[[ "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'merge_base="$(git merge-base "$BASE_SHA" "$SOURCE_SHA")"',
        '[[ "$merge_base" =~ ^[0-9a-f]{40}$ ]]',
        'git merge-base --is-ancestor "$merge_base" "$BASE_SHA"',
        'git merge-base --is-ancestor "$merge_base" "$SOURCE_SHA"',
        'changed="$RUNNER_TEMP/v09-changed-paths.bin"',
        'git diff --no-renames --name-only -z "$merge_base" "$SOURCE_SHA" > "$changed"',
    )
    if executable_shell != expected_shell:
        return False
    expected_source = textwrap.dedent(r"""          import os
          import pathlib
          import sys
          import tomllib
          from tools.v09_qualification_scope import requires_full_qualification

          changed_path = pathlib.Path(sys.argv[1])
          output_path = pathlib.Path(sys.argv[2])
          contract = tomllib.loads(
              pathlib.Path("contracts/v09-qualification-routing.toml").read_text(encoding="utf-8")
          )
          changed = sorted(
              {
                  os.fsdecode(path)
                  for path in changed_path.read_bytes().split(b"\0")
                  if path
              }
          )
          full = requires_full_qualification(changed, contract)
          with output_path.open("a", encoding="utf-8") as handle:
              handle.write(f"full_qualification={'true' if full else 'false'}\n")
          print("v0.9 lane:", "full-qualification" if full else "exact-source-regression")
          for path in changed:
              print(path)""")
    try:
        return ast.dump(ast.parse(source), include_attributes=False) == ast.dump(
            ast.parse(expected_source), include_attributes=False
        )
    except SyntaxError:
        return False


TOOLCHAIN_DATA_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/vm-acceptance.yml",
    ".github/workflows/v04-durability-vm.yml",
    ".github/workflows/v04-enospc-recovery-vm.yml",
    ".github/workflows/v05-executor-verifier-vm.yml",
    ".github/workflows/v06-managed-lifecycle-vm.yml",
    ".github/workflows/v07-library-qualification.yml",
    ".github/workflows/v08-agent-qualification.yml",
    ".github/workflows/v09-qualification.yml",
    ".github/workflows/v010-qualification.yml",
    ".github/workflows/v010-shell-runtime-qualification.yml",
    ".github/workflows/reusable-release-build.yml",
)


# Local shell scripts and composite actions are inspected as a superset of the
# workflow invocation graph. A caller cannot hide a new toolchain source in an
# intermediate helper, even when the helper is invoked before the workflow's
# own guarded load.
REVIEWED_LOCAL_SOURCES = {
    # These commands execute via SSH on the isolated qualification guest,
    # not in the repository checkout. Only the exact reviewed lines are exempt.
    "scripts/qualification/v09-adversarial-guest.sh": {
        (
            'if result="$(remote "sudo -n sh -c \'test -s \\"$status_pa'
            'th\\" && { cat \\"$status_path\\"; printf \\"__LINURA_Q8_OUT'
            'PUT__\\\\n\\"; cat \\"$output_path\\"; }\'" 2>/dev/null)"; the'
            "n"
        ),
        (
            'if result="$(remote "sudo -n sh -c \'test -s \\"$status_pa'
            'th\\" && { cat \\"$status_path\\"; printf \\"__LINURA_PUBLIC'
            '_BOOTSTRAP_OUTPUT__\\\\n\\"; cat \\"$output_path\\"; }\'" 2>/d'
            'ev/null)"; then'
        ),
        'remote "sudo -n bash -lc $quoted"',
    },
    ".github/actions/ubuntu-apt-input-cache/action.yml": {
        'os_id="$(. /etc/os-release && printf \'%s\' "$ID")"',
        'os_version="$(. /etc/os-release && printf \'%s\' "$VERSION_ID")"',
    },
    "scripts/setup_codex_environment.sh": {
        "source scripts/lib/codex_source_state.sh",
        'source "$RUSTUP_BOOTSTRAP_LIB"',
    },
    "scripts/preflight_codex_environment.sh": {
        "source scripts/lib/codex_source_state.sh",
    },
    "qualification/v010/workstation-acceptance/launch-interactive.sh": {},
    "tests/acceptance/v05/qualify-guest.sh": {
        'source <(/usr/libexec/linura/v05-binding "$target")',
    },
}
TOOLCHAIN_VALUES_READ = (
    "read -r ACTIONLINT_SHA256 ACTIONLINT_VERSION CARGO_AUDIT_VERSION "
    "HOST_ARCH HOST_OS PYTHON_MAJOR_MINOR PYTHON_PIP_VERSION PYTHON_RELEASE "
    "RUFF_VERSION RUSTUP_INIT_SHA256 RUSTUP_VERSION RUST_VERSION "
    '<<<"$toolchain_values"'
)
TOOLCHAIN_VALUES_NONEMPTY = (
    ': "${ACTIONLINT_SHA256:?}" "${ACTIONLINT_VERSION:?}" "${CARGO_AUDIT_VERSION:?}" '
    '"${HOST_ARCH:?}" "${HOST_OS:?}" "${PYTHON_MAJOR_MINOR:?}" '
    '"${PYTHON_PIP_VERSION:?}" "${PYTHON_RELEASE:?}" "${RUFF_VERSION:?}" '
    '"${RUSTUP_INIT_SHA256:?}" "${RUSTUP_VERSION:?}" "${RUST_VERSION:?}"'
)

TOOLCHAIN_WORKFLOW_LOAD = (
    'toolchain_values="$(python3 -I -S tools/check_toolchain_env.py '
    '--values tools/codex/versions.env)"'
)
TOOLCHAIN_LOCAL_LOAD = (
    'toolchain_values="$(python3 -I -S tools/check_toolchain_env.py '
    '--values "$VERSION_CONTRACT")"'
)
TOOLCHAIN_WORKSTATION_LOAD = (
    'toolchain_values="$(python3 -I -S "$build_root/tools/check_toolchain_env.py" '
    '--values "$build_root/tools/codex/versions.env")" \\'
)


TOOLCHAIN_LOCAL_LOADS = {
    "scripts/setup_codex_environment.sh": (
        TOOLCHAIN_VALUES_READ,
        TOOLCHAIN_LOCAL_LOAD,
    ),
    "scripts/preflight_codex_environment.sh": (
        TOOLCHAIN_VALUES_READ,
        TOOLCHAIN_LOCAL_LOAD,
    ),
    "qualification/v010/workstation-acceptance/launch-interactive.sh": (
        TOOLCHAIN_VALUES_READ,
        '|| fail "exact-source toolchain contract rejected"',
    ),
}


def dynamic_shell_execution(
    source: str, *, literal_sources: bool = False, literal_interpreters: bool = False
) -> bool:
    """Recognize execution requiring review without resolving shell inputs.

    Inspect shell command boundaries, then tokenize the command prefix so
    quoting, concatenated words, assignment prefixes and builtin wrappers do
    not hide an executable expansion. This is a conservative static check,
    not a general shell interpreter. Exact-file reviews cover existing
    dynamic/nested launchers; an unchanged call after a new reassignment is
    not an exception. Literal interpreter recognition deliberately ignores
    arguments: every shell input mechanism requires the same review.
    """
    source = source.replace("\\\n", "")
    boundary = re.compile(
        r"(?:^|[\n;&|(]\s*|"
        r"\b(?:if|elif|else|while|until|then|do|coproc)\s+|"
        r"\btime\s+(?:-p\s+)?|(?<!\w)!\s+|\brun:\s*|"
        r"\bcase\b[^;\n]*\bin\s+[^;\n]*\)\s*|"
        r"(?m:^\s*(?:[A-Za-z0-9_*?|.\[\]-]+|\"[^\"\n]*\"|'[^'\n]*')\)\s*))"
    )
    wrappers = {"command", "builtin", "exec", "env", "sudo", "nohup", "time", "{"}
    option_arguments = {
        "env": {"-u", "--unset", "-C", "--chdir"},
        "exec": {"-a"},
        "sudo": {"-u", "-g", "-h", "-p", "-C", "-U", "--user", "--group", "--host"},
        "time": {"-f", "-o", "--format", "--output"},
    }
    for match in boundary.finditer(source):
        line_start = source.rfind("\n", 0, match.start()) + 1
        before = source[line_start : match.start()]
        context = source[line_start : match.end()]
        if before.rfind("[[") > before.rfind("]]") and context.rfind(
            "$("
        ) < before.rfind("[["):
            continue
        if match.group().startswith("(") and re.search(
            r"[A-Za-z_][A-Za-z0-9_]*=\s*$", before
        ):
            continue
        tail = source[match.end() :].split("\n", 1)[0]
        if not tail or tail.lstrip().startswith("#"):
            continue
        lexer = shlex.shlex(tail, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        wrapped = False
        wrapper = ""
        skip_argument = False
        try:
            for word in lexer:
                if skip_argument:
                    skip_argument = False
                    continue
                if word in {";", "&", "&&", "|", "||", "(", ")"}:
                    break
                if word in {"<", ">", ">>", "<<<", "<&", ">&", "<>"}:
                    skip_argument = True
                    continue
                if word.isdecimal():
                    continue
                if re.match(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=", word):
                    continue
                # Quote removal concatenates e.g. "$load"er into one word.
                # Treat even literal dollar-bearing executable names as
                # unsupported rather than guessing at expansion semantics.
                if "$" in word or "`" in word:
                    if not literal_sources:
                        return True
                    break
                if literal_sources and word in {"source", ".", "eval"}:
                    return True
                if (
                    literal_interpreters
                    and wrapped
                    and wrapper == "env"
                    and (word.startswith("-S") or word.startswith("--split-string"))
                ):
                    # env's command-string parser is outside this grammar.
                    return True
                if literal_interpreters and Path(word).name in {
                    "bash",
                    "dash",
                    "zsh",
                    "ksh",
                    "ash",
                    "mksh",
                    "sh",
                }:
                    # A shell can execute stdin, a pipe, a descriptor, a
                    # here-document or a script. Do not infer safety from
                    # its option spelling or try to resolve the input path.
                    return True
                if literal_interpreters and Path(word).name in {"busybox", "toybox"}:
                    wrapped = True
                    wrapper = Path(word).name
                    continue
                if Path(word).name in wrappers:
                    wrapped = True
                    wrapper = Path(word).name
                    continue
                if wrapped and word.startswith("-"):
                    if wrapper == "command" and word in {"-v", "-V"}:
                        break
                    skip_argument = word in option_arguments.get(wrapper, set())
                    continue
                break
        except ValueError:
            # A multiline or encoded command prefix with expansions is
            # outside the reviewed grammar. Arguments of a known literal
            # command were never requested from the lexer.
            if (
                not literal_sources
                and not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", tail)
                and re.match(r"[^\s]*[$`]", tail)
            ):
                return True
    return False


# Digests bind exceptions to complete reviewed files, including every variable
# definition. Adding an invocation or changing a variable invalidates review.
REVIEWED_SHELL_EXECUTION = {
    # Qualification entrypoints retain their exact reviewed guest commands,
    # recorder paths and callback helpers. Here-doc data is conservatively
    # included in the scan; the digest also binds those opaque bodies.
    "scripts/prepare_qualification_storage.sh": "4967e7217aeb4644fb645f47e1f47c4983785e4a134c146ab1dbea770bd55546",
    "qualification/v010/shell-runtime/prepare-substrate.sh": "3343b0bb022e493a9cba6f28d22aa2c31625d2fd43d7671d96edba3afccda3b9",
    "qualification/v010/shell-runtime/run-shell-runtime.sh": "fb0bd980d983d3d694b0a6f8faf39976cee81ed94031edb09e33a1cae351cfb7",
    "qualification/v010/shell-runtime/start-vm.sh": "76d2284b847b15564c9c3494b2b508d9ba8dacf941cef3e7ae6872010b911c71",
    "qualification/v010/workstation-acceptance/capture-hardware-session.sh": "ce2257338be8b6b1f9b07248102f28808bbbecf83277f886163127e244d11ad3",
    "qualification/v010/workstation-acceptance/launch-interactive.sh": "1c8ed5fc180526a8176e7a88635fae9b122daa0b64090e826ec3e3c6af957dd6",
    "qualification/v010/workstation-acceptance/run-hardware-qualification.sh": "fa08f7a5cf050d9692de40227b8e40668859d54e801318dfa7dfe7181ed90b72",
    "qualification/v010/workstation-acceptance/run-live-session.sh": "e8013a8b52a6eeac5b53e1bfa3861a2a4879e4b33978f3d22b08ce634e06360f",
    "scripts/qualification/v09-adversarial-guest.sh": "f4a12a53b830ceffb7c8ea3c30ab67f3bed9c84de763c8db205d48e75aaa9c9f",
    "tests/acceptance/v06/qualify-guest.sh": "44031433394771a32cb85f8875ed1f88e90deab3f263de7e15a54ec0dc305126",
    "tests/acceptance/v06/qualify-host.sh": "ff3f2282b2ca8b6674f6eb6cea65f09dcaaa53088ea3f3515bba0ea2807222d8",
    "tests/acceptance/v06/qualify-native-session.sh": "203a7a695ef7fe4e9268477e60861d9eef611f429075ee91fefb6b29705de777",
    # Development-only tools run at the caller's existing permissions.
    "scripts/lib/bootstrap_rustup.sh": "60db235ffa3f448b1182665285dc3347f017cbcb5785f087f056c3b30e836ad8",
    # This library executes before validation to protect source integrity even
    # when the validator fails. Bind its entire body, not selected commands.
    "scripts/lib/codex_source_state.sh": "3b27ccc177aeb948df5dd4620dcb5f18dd1a570c91511adc847951b295de6281",
    "scripts/maintain_codex_environment.sh": "74f26eccb9362479490f5ad954d6c8570f116bddd75894fd647f783775e5bcf4",
    "scripts/lint_github_workflows.sh": "ce5b656f70d742885521fd7d5fddc0fdd7f2e7f0db984f7fcfb17600142a8bd3",
    "scripts/preflight_codex_environment.sh": "18d48028b461ada8691cb5abab14d045cce9993034e2bee7009d36012fac07c0",
    "scripts/run_codex.sh": "b6928e621faea0581ab6d91e55624d1572216f7b95e2d31b2cfe4495188dd54c",
    "scripts/setup_codex_environment.sh": "8cf16b8ae854b19988a50d2cee6bb70e8bb56500dceaefceef7814c3f745d38a",
}

PREVALIDATION_SHELL_FILES = (
    "scripts/setup_codex_environment.sh",
    "scripts/preflight_codex_environment.sh",
    "scripts/maintain_codex_environment.sh",
    "scripts/lib/codex_source_state.sh",
)


def repository_source_files(root: Path) -> list[Path] | None:
    """Return tracked and non-ignored untracked files for a real checkout.

    Temporary test fixtures are not Git repositories and intentionally fall
    back to the filesystem walk below. In a checkout, Git's inventory avoids
    treating ignored build outputs or nested worktrees as repository source
    while still auditing new files before they are staged.
    """
    if not (root / ".git").exists():
        return None
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
            ],
            capture_output=True,
            check=False,
            env=environment,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("repository source inventory unavailable") from error
    if result.returncode != 0:
        raise ValueError("repository source inventory unavailable")
    found: list[Path] = []
    names: set[str] = set()
    for raw_name in result.stdout.split(b"\0"):
        if not raw_name:
            continue
        try:
            name = raw_name.decode("utf-8")
        except UnicodeError as error:
            raise ValueError("non-UTF-8 repository source path") from error
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or relative.as_posix() != name
            or name in names
        ):
            raise ValueError("unsafe repository source path")
        names.add(name)
        found.append(root.joinpath(*relative.parts))
    return found


def local_shell_sources_guarded(root: Path) -> list[str]:
    """Fail closed on source/evaluation added anywhere in local shell inputs."""
    failures: list[str] = []
    for relative in PREVALIDATION_SHELL_FILES:
        path = root / relative
        if not path.is_file() or any(
            part.is_symlink() for part in (path, *path.parents)
        ):
            failures.append(
                f"{relative}: missing or symlinked pre-validation bootstrap"
            )
    candidates: set[Path] = set()
    # Scan the whole source tree, not a directory allowlist: workflows can
    # invoke helpers from the repository root, tools/, or any new directory.
    # Ignore generated dependency/build trees, which are not source inputs.
    generated = {".git", "target", "node_modules", ".venv", "__pycache__"}
    legacy_extensionless = {
        "scripts",
        "qualification",
        "packaging",
    }
    try:
        repository_files = repository_source_files(root)
    except ValueError as error:
        return [str(error)]
    if repository_files is None:
        repository_files = []
        for directory, subdirectories, filenames in os.walk(root, followlinks=False):
            subdirectories[:] = [
                name for name in subdirectories if name not in generated
            ]
            repository_files.extend(Path(directory) / name for name in filenames)
    for path in repository_files:
        filename = path.name
        if path.is_file() or path.is_symlink():
            relative = path.relative_to(root)
            is_action = relative.parts[:2] == (".github", "actions") and filename in {
                "action.yml",
                "action.yaml",
            }
            if path.suffix in {".sh", ".bash"} or is_action:
                candidates.add(path)
            else:
                legacy = not path.suffix and (
                    relative.parts[0] in legacy_extensionless
                    or relative.parts[:2]
                    in {
                        ("tests", "acceptance"),
                        (".github", "actions"),
                    }
                )
                if legacy or (not path.suffix and path.is_symlink()):
                    candidates.add(path)
                    continue
                # Git checkout preserves executable modes. A shebang-free
                # executable with any extension can run as shell via ENOEXEC,
                # so suffix and shebang classification alone are not enough.
                if path.is_symlink():
                    continue
                try:
                    with path.open("rb") as stream:
                        shebang = stream.readline(256).strip()
                    # An executable with a non-shell shebang runs through
                    # that interpreter, not through Bash's ENOEXEC fallback.
                    if path.stat().st_mode & 0o111 and not shebang.startswith(b"#!"):
                        candidates.add(path)
                        continue
                except OSError:
                    failures.append(
                        f"{relative.as_posix()}: unreadable shell candidate"
                    )
                    continue
                if shebang.startswith(b"#!") and re.search(
                    rb"(?:/|[ \t])(?:bash|dash|ksh|zsh|ash|mksh|sh)(?:[ \t]|$)",
                    shebang,
                ):
                    candidates.add(path)
    # An explicit shell interpreter can execute a file with any suffix and
    # without a shebang. Follow literal repository-local interpreter targets
    # transitively, including invocations from workflow run blocks.
    shell_invocation = re.compile(
        r"(?<![A-Za-z0-9_./-])(?:/(?:usr/)?bin/)?"
        r"(?:bash|dash|zsh|ksh|ash|mksh|sh)[ \t]+"
        r"(?:(?:-(?![A-Za-z]*c(?=[ \t]))[A-Za-z]+|"
        r"--[A-Za-z][A-Za-z0-9-]*|--)[ \t]+)*"
        r"(?P<quote>['\"]?)(?P<path>(?!-)(?:\./)?[A-Za-z0-9_.+-]+"
        r"(?:/[A-Za-z0-9_.+-]+)*)(?P=quote)(?=$|[ \t;&|)])"
    )
    # Audit literal path operands following the first apparent script as
    # well: -O/-o and --rcfile/--init-file consume an argument before the
    # actual script, and startup files themselves can execute shell code.
    shell_path_operand = re.compile(
        r"(?<![A-Za-z0-9_./-])(?P<quote>['\"]?)"
        r"(?P<path>(?:\./)?[A-Za-z0-9_.+-]+"
        r"(?:/[A-Za-z0-9_.+-]+)*)(?P=quote)(?=$|[ \t;&|)])"
    )
    pending = list(candidates)
    pending.extend(sorted((root / ".github/workflows").glob("*.y*ml")))
    inspected: set[Path] = set()
    while pending:
        caller = pending.pop()
        if caller in inspected:
            continue
        inspected.add(caller)
        if caller.is_symlink():
            continue
        try:
            content = caller.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for line in content.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for match in shell_invocation.finditer(line):
                operands = [match.group("path")]
                operands.extend(
                    token.group("path")
                    for token in shell_path_operand.finditer(line[match.end() :])
                )
                for operand in operands:
                    relative = Path(operand)
                    if ".." in relative.parts:
                        continue
                    invoked = root / relative
                    if (
                        invoked.is_file() or invoked.is_symlink()
                    ) and invoked not in candidates:
                        candidates.add(invoked)
                        pending.append(invoked)
    for path in sorted(candidates):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            failures.append(f"{relative}: symlinked shell entrypoint")
            continue
        try:
            raw = path.read_bytes()
            content = raw.decode("utf-8")
            lines = content.splitlines()
        except (OSError, UnicodeError):
            failures.append(f"{relative}: unreadable shell entrypoint")
            continue
        reviewed_digest = REVIEWED_SHELL_EXECUTION.get(relative)
        if (
            reviewed_digest is not None
            and hashlib.sha256(raw).hexdigest() != reviewed_digest
        ) or (
            reviewed_digest is None
            and dynamic_shell_execution(content, literal_interpreters=True)
        ):
            failures.append(f"{relative}: unreviewed shell execution")
        active = [
            line.strip()
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        ]
        approved = REVIEWED_LOCAL_SOURCES.get(relative, set())
        for index, line in enumerate(active):
            invokes_source = (
                re.search(
                    r"(?:^|[;&|({)]\s*|"
                    r"\b(?:if|elif|else|while|until|then|do|coproc)\s+(?:!\s+)?|"
                    r"\btime\s+(?:-p\s+)?(?:!\s+)?|"
                    r"(?<!\w)!\s+)"
                    r"(?:builtin\s+(?:--\s+)?|"
                    r"command\s+(?:-[pVv]\s+)*(?:--\s+)?)?"
                    r"(?:source|\.)\s+",
                    line,
                )
                is not None
            )
            invokes_shell_eval = (
                re.search(
                    r"(?:^|[;&|({)]\s*|"
                    r"\b(?:if|elif|else|while|until|then|do|coproc)\s+(?:!\s+)?|"
                    r"\btime\s+(?:-p\s+)?(?:!\s+)?)"
                    r"(?:builtin\s+(?:--\s+)?|"
                    r"command\s+(?:-[pVv]\s+)*(?:--\s+)?)?"
                    r"eval\s+",
                    line,
                )
                is not None
            )
            # A composite action may execute the source in a run: scalar.
            inline_source = (
                re.search(r"""\brun:\s*(?:['"]\s*)?(?:source|\.|eval)\s+""", line)
                is not None
            )
            if (
                invokes_source
                or invokes_shell_eval
                or inline_source
                or dynamic_shell_execution(line, literal_sources=True)
            ):
                if line not in approved:
                    failures.append(
                        f"{relative}: unreviewed local shell source/evaluation"
                    )
            if (
                "tools/codex/versions.env" in line
                and relative not in TOOLCHAIN_LOCAL_LOADS
            ):
                failures.append(f"{relative}: unreviewed local toolchain reference")
        if relative not in TOOLCHAIN_LOCAL_LOADS:
            continue
        source, guard = TOOLCHAIN_LOCAL_LOADS[relative]
        if active.count(source) != 1:
            failures.append(
                f"{relative}: missing or duplicated reviewed toolchain source"
            )
            continue
        index = active.index(source)
        if relative.startswith("scripts/"):
            if (
                'readonly VERSION_CONTRACT="tools/codex/versions.env"' not in active
                or active.count(guard) != 1
                or index == 0
                or active[index - 1] != guard
                or "set -euo pipefail" not in active[:index]
            ):
                failures.append(
                    f"{relative}: toolchain data load must immediately follow validation"
                )
        elif (
            index < 2
            or active[index - 1] != guard
            or active[index - 2] != TOOLCHAIN_WORKSTATION_LOAD
            or "set -euo pipefail" not in active[:index]
        ):
            failures.append(f"{relative}: exact-source toolchain guard is missing")
        if index + 1 >= len(active) or active[index + 1] != TOOLCHAIN_VALUES_NONEMPTY:
            failures.append(f"{relative}: toolchain fields were not verified nonempty")
    return failures


REVIEWED_PREVALIDATION_PREFIXES: dict[tuple[str, str], str] = {
    (
        ".github/workflows/applicable-qualification.yml",
        "shadow",
    ): "49c2287f6bfc4b5f9d4b622de908b8f95c9f4c364f6948e6a47250e2ab26144e",
    (
        ".github/workflows/branch-hygiene.yml",
        "cleanup",
    ): "55c85bf2b2eb4c3e6c096a82946eb583b158593372337f58e53ff4991aeb4da5",
    (
        ".github/workflows/crates-io-publish.yml",
        "bind-verification",
    ): "08bcc0a34a59c73a2c0069caffa34d1d94e17cc6b392d715566076bc9b6c5288",
    (
        ".github/workflows/crates-io-publish.yml",
        "qualify",
    ): "2c68cb5ffe2682be317b731c5ca4cae843ee1736509b52dc4f932c5b722309ba",
    (
        ".github/workflows/crates-io-publish.yml",
        "publish",
    ): "2c68cb5ffe2682be317b731c5ca4cae843ee1736509b52dc4f932c5b722309ba",
    (
        ".github/workflows/post-release-cleanup.yml",
        "cleanup",
    ): "ff354c808feeeae976f7faea52f49e66d23dc853d70df23dd8aa61bdb101834f",
    (
        ".github/workflows/post-release-closure.yml",
        "close",
    ): "c4838db1a91f2f7ad890324a001a9ee479565972aab7fb26b34c9d5f0ec5a040",
    (
        ".github/workflows/publish-qualification-evidence.yml",
        "admission",
    ): "af493c046fce964bd29b3b42c4a684849ad6db26c5131b203b8d4a2a5cfa4c92",
    (
        ".github/workflows/publish-qualification-evidence.yml",
        "archive",
    ): "dd67be2797cb6789ff22431efab4b68ce3abd8ec5ed7d8f1c14491e78b43e90f",
    (
        ".github/workflows/release-authorization.yml",
        "qualify",
    ): "55c85bf2b2eb4c3e6c096a82946eb583b158593372337f58e53ff4991aeb4da5",
    (
        ".github/workflows/release-authorization.yml",
        "authorize",
    ): "018b13be4cde08c97c17fa29a2e50f5f48316284901f4cd1cc2937ec6a221c73",
    (
        ".github/workflows/release-preparation.yml",
        "qualify",
    ): "55c85bf2b2eb4c3e6c096a82946eb583b158593372337f58e53ff4991aeb4da5",
    (
        ".github/workflows/release-preparation.yml",
        "prepare",
    ): "018b13be4cde08c97c17fa29a2e50f5f48316284901f4cd1cc2937ec6a221c73",
    (
        ".github/workflows/release-promotion.yml",
        "closure-readiness",
    ): "3e58d636d234ad37905e5e5694286a00f95da48393253d93d7054e1125f09214",
    (
        ".github/workflows/release-proof-dispatch.yml",
        "dispatch",
    ): "ff354c808feeeae976f7faea52f49e66d23dc853d70df23dd8aa61bdb101834f",
    (
        ".github/workflows/release-verification.yml",
        "verify",
    ): "e1e740b0276cec5082cfde7c7fe74c8178d3a7f9abbe10265fbde69eca58d0a7",
    (
        ".github/workflows/release.yml",
        "validate",
    ): "1aec76767ae438244c7833c8b00753599e34afece7a62663302d867899f25948",
    (
        ".github/workflows/trusted-release-proof.yml",
        "validate",
    ): "55c85bf2b2eb4c3e6c096a82946eb583b158593372337f58e53ff4991aeb4da5",
    (
        ".github/workflows/trusted-release-proof.yml",
        "aggregate-proof",
    ): "8e29d459d72e94b0f412f73a21aa42f37c25330af9b1b7d8aa3049d8d3f9a0f3",
}

# These minimal API handoffs / sealed-artifact upload jobs deliberately have
# no repository checkout or repository-code execution. Bind complete bodies,
# not display names, so adding any local helper invalidates the exception.
REVIEWED_CHECKOUT_FREE_JOBS: dict[tuple[str, str], str] = {
    (
        ".github/workflows/crates-io-publish.yml",
        "dispatch-closure",
    ): "03568e533ccc837c256321fa915f91f4f6de9cd66bc34ca25f20d77036b26de8",
    (
        ".github/workflows/publish-qualification-evidence.yml",
        "preflight",
    ): "606d24b652507f6701c4530124164be2223ab46a4ff428786f28f3c40873b415",
    (
        ".github/workflows/release-closure-handoff.yml",
        "handoff",
    ): "f56a9dee8e2fb1c9ffdcdd73cfa886ae60b1a44381a6d642a319537f5f85671a",
    (
        ".github/workflows/release-promotion.yml",
        "dispatch",
    ): "1f21e1cfc9c585667776ca3177f909f40e18b45fb4ca1cca5c2545532e72ec2e",
    (
        ".github/workflows/release.yml",
        "publish-pypi",
    ): "634bf38c9884d3e8b894f306edf92349ecef49c8f90146f93f6c4334ad165211",
    (
        ".github/workflows/release.yml",
        "verification-dispatch",
    ): "cc17d4287dca14b570371270399887f7b049f2671b89ea5ad2eefba45d02f043",
    (
        ".github/workflows/trusted-release-proof.yml",
        "dispatch-promotion",
    ): "8a5129641442d4e6110ee6e6f71316217bb15f801305e5c31463f8f50f85f187",
}

TOOLCHAIN_WORKFLOW_VALIDATE = (
    "python3 -I -S tools/check_toolchain_env.py tools/codex/versions.env"
)

TOOLCHAIN_SUCCESS_CONDITIONS = frozenset(
    "${{ " + status + "() && steps.toolchain_data.outcome == 'success' }}"
    for status in ("always", "failure")
)

# This second checkout is data-only evidence in a separate directory. It must
# never replace the trusted admission code or become an executable worktree.
REVIEWED_SECONDARY_CHECKOUTS = {
    (
        ".github/workflows/publish-qualification-evidence.yml",
        "admission",
    ): "1efb40ab0e23e823271ba92cf95d2b6ee9c5ec3a0102903a61d77b9225b7b0ed",
}


def _workflow_jobs(workflow: str, relative: str) -> tuple[str, bool] | None:
    """Classify all jobs; only exact reviewed checkout-free bodies are omitted."""
    jobs = section(workflow, "jobs")
    headings = list(re.finditer(r"(?m)^jobs:[ \t]*\n", workflow))
    if jobs is None or len(headings) != 1:
        return None
    headers = list(re.finditer(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*$", jobs))
    names = [match[1] for match in headers]
    if not names or len(names) != len(set(names)):
        return None
    if sum(
        bool(line.strip())
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip(" ")) <= 2
        for line in jobs.splitlines()
    ) != len(headers):
        return None
    filtered = workflow[: headings[0].end()]
    executable = False
    for index, header in enumerate(headers):
        ending = headers[index + 1].start() if index + 1 < len(headers) else len(jobs)
        name = header[1]
        body = jobs[header.end() + 1 : ending]
        reviewed = REVIEWED_CHECKOUT_FREE_JOBS.get((relative, name))
        if reviewed is not None:
            if hashlib.sha256(body.encode("utf-8")).hexdigest() != reviewed:
                return None
            continue
        steps = section(body, "steps", 4)
        if steps is None:
            uses = re.findall(r"(?m)^    uses: (.+)$", body)
            if (
                len(uses) != 1
                or re.fullmatch(
                    r"\./\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", uses[0]
                )
                is None
            ):
                return None
        else:
            # A second checkout could replace already validated input. Status
            # overrides may run after later failures, never after this guard
            # fails. Default conditions retain GitHub's implicit success().
            validation = workflow_step(
                body, 4, "name", "Validate repository toolchain data"
            )
            if 'test "$GITHUB_SHA" = "$SOURCE_SHA"' in executable_run_block(
                validation, 4
            ):
                if re.findall(
                    r"(?m)^      SOURCE_SHA: (.+)$", section(body, "env", 4) or ""
                ) != ["${{ inputs.source_sha }}"]:
                    return None
            if len(re.findall(r"(?m)^        id: toolchain_data$", steps)) != 1:
                return None
            checkouts = re.findall(r"(?m)^\s*(?:- )?uses: actions/checkout@", steps)
            entries = list(re.finditer(r"(?m)^      - .+$", steps))
            if any(
                re.fullmatch(r"      - (?:name|uses|run|id|if):[ \t]+.+", entry[0])
                is None
                for entry in entries
            ):
                return None
            if sum(
                bool(line.strip())
                and not line.lstrip().startswith("#")
                and len(line) - len(line.lstrip(" ")) <= 6
                for line in steps.splitlines()
            ) != len(entries):
                return None
            checkout_bodies = [
                steps[
                    entry.start() : entries[pos + 1].start()
                    if pos + 1 < len(entries)
                    else len(steps)
                ]
                for pos, entry in enumerate(entries)
                if re.search(
                    r"(?m)^\s*(?:- )?uses: actions/checkout@",
                    steps[
                        entry.start() : entries[pos + 1].start()
                        if pos + 1 < len(entries)
                        else len(steps)
                    ],
                )
            ]
            if len(checkouts) != len(checkout_bodies) or not checkout_bodies:
                return None
            if len(checkout_bodies) > 1 and (
                len(checkout_bodies) != 2
                or hashlib.sha256(checkout_bodies[1].encode("utf-8")).hexdigest()
                != REVIEWED_SECONDARY_CHECKOUTS.get((relative, name))
            ):
                return None
            step_lines = steps.splitlines()
            for index, line in enumerate(step_lines):
                condition_match = re.fullmatch(
                    r"(?:        |      - )if:[ \t]*(.*)", line
                )
                if condition_match is None:
                    continue
                condition = condition_match[1].strip()
                if not condition or condition[0] in "#|>!&*{[":
                    return None
                following = next(
                    (
                        value
                        for value in step_lines[index + 1 :]
                        if value.strip() and not value.lstrip().startswith("#")
                    ),
                    "",
                )
                if following and len(following) - len(following.lstrip()) > 8:
                    return None
                if re.search(r"\b(?:always|failure|cancelled|success)\s*\(", condition):
                    if condition not in TOOLCHAIN_SUCCESS_CONDITIONS | {
                        "success()",
                        "${{ success() }}",
                    }:
                        return None
            executable = True
        filtered += jobs[header.start() : ending]
    # Do not discard root metadata that YAML permits after the jobs mapping.
    filtered += workflow[headings[0].end() + len(jobs) :]
    return filtered, executable


def toolchain_load_follows_checkout(
    lines: list[str], step_start: int, workflow_name: str | None = None
) -> bool:
    """Nothing executable may precede a job's validated configuration load.

    Enumerating interpreters cannot prove what arbitrary repository code does.
    Require a closed structural prefix instead: the pinned checkout action
    followed by the loader. The only exceptions are immutable Python setup
    and the exact publisher provenance/bootstrap prefix. Arbitrary helpers,
    regardless of their interpreter, cannot acquire an exception by name.
    """
    steps_start = step_start - 1
    while steps_start >= 0 and lines[steps_start].strip() != "steps:":
        steps_start -= 1
    if steps_start < 0 or lines[steps_start] != "    steps:":
        return False
    if workflow_name is not None:
        job = next(
            (
                line.strip()[:-1]
                for line in reversed(lines[:steps_start])
                if re.fullmatch(r"  [A-Za-z_][A-Za-z0-9_-]*:", line)
            ),
            "",
        )
        reviewed = REVIEWED_PREVALIDATION_PREFIXES.get((workflow_name, job))
        if reviewed is not None:
            return (
                hashlib.sha256(
                    "\n".join(lines[steps_start + 1 : step_start]).encode("utf-8")
                ).hexdigest()
                == reviewed
            )
    prefix = [
        line.split(" #", 1)[0].rstrip()
        for line in lines[steps_start + 1 : step_start]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not prefix or prefix[0] != (
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    ):
        return False
    # Preserve the publisher's existing source-attestation-before-repository-
    # execution boundary. This binds checkout, pinned Node setup and the full
    # exact provenance/publisher-test step, not just their display labels.
    if hashlib.sha256(
        "\n".join(lines[steps_start + 1 : step_start]).encode("utf-8")
    ).hexdigest() == (
        "9fcb7b997ee39578a055a2f4a7fae4c4c24a857aaa132e4eb22625a45df71c11"
    ):
        return True
    next_step = next(
        (
            index
            for index, line in enumerate(prefix[1:], 1)
            if line.startswith("      - ")
        ),
        len(prefix),
    )
    if prefix[next_step:] not in (
        [],
        [
            "      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "        with:",
            '          python-version: "3.12.10"',
        ],
    ):
        return False
    prefix = prefix[:next_step]
    if len(prefix) == 1:
        return True
    if prefix[1] != "        with:":
        return False
    if len(prefix) < 3:
        return False
    seen: set[str] = set()
    for line in prefix[2:]:
        match = re.fullmatch(
            r"          (fetch-depth|persist-credentials|ref): (.+)", line
        )
        if match is None or match[1] in seen:
            return False
        seen.add(match[1])
        if match[1] == "fetch-depth" and match[2] != "0":
            return False
        if match[1] == "persist-credentials" and match[2] != "false":
            return False
        if match[1] == "ref" and match[2] not in {
            "${{ inputs.source_sha }}",
            "${{ inputs.source_sha || github.sha }}",
            "${{ github.event.pull_request.head.sha || github.sha }}",
            "${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}",
        }:
            return False
    return True


WORKFLOW_EMPTY_STARTUP_ENV = frozenset(
    ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "NODE_OPTIONS")
)

# Protected loader jobs accept only reviewed application data, never ambient
# interpreter/executable selection. New names require an explicit review here;
# extending a denylist of startup hooks cannot close this boundary.
TOOLCHAIN_DATA_ENV_KEYS = frozenset(
    (
        "ACCEPTANCE_CONTRACT",
        "ACCEPTANCE_SCENARIO",
        "ADMISSION_SHA",
        "ADVERSARIAL_ROOT",
        "APPROVAL_REASON",
        "ARCH_ARCHIVE_URL",
        "ARTIFACT_DIR",
        "ATTEMPT",
        "AUTHORITY_SHA",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "BASE_IMAGE_CHECKSUM_URL",
        "BASE_IMAGE_SHA256",
        "BASE_IMAGE_URL",
        "BASE_SHA",
        "BRANCH",
        "CARGO_REGISTRY_TOKEN",
        "CATEGORY",
        "CLOSURE_SHA",
        "CONTRACT_ENVELOPE_ROOT",
        "CRATES_IO_RUN_ID",
        "CRATE_PACKAGE_SHA256",
        "CRATE_VERSION",
        "EVENT_NAME",
        "EVIDENCE_ROOT",
        "EXPECTED_CHANGED_FILES",
        "GH_REPO",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HEAD_SHA",
        "INPUT_CRATES_IO_RUN_ID",
        "INPUT_TAG",
        "INPUT_VERIFICATION_RUN_ID",
        "LINURA_EXPECTED_SOURCE_SHA",
        "LINURA_STORAGE_ID",
        "LINURA_STORAGE_ROOT",
        "LINURA_STORAGE_CLASS",
        "LINURA_V07_EVIDENCE_DIR",
        "PACKAGE_SHA256",
        "PAYLOAD_DIR",
        "PROMOTION_RUN_ID",
        "PROOF_DIR",
        "PROOF_ROOT",
        "PROOF_RUN_ID",
        "PR_NUMBER",
        "PUBLISHED_AT",
        "PYPI_DIR",
        "PYTHON_WHEEL_SOURCE_DATE_EPOCH",
        "QUALIFICATION_DISK_GIB",
        "QUALIFICATION_ENVIRONMENT_ID",
        "QUALIFICATION_GPU_DEVICE_ID",
        "QUALIFICATION_GPU_PCI_BDF",
        "QUALIFICATION_GPU_VENDOR_ID",
        "QUALIFICATION_NIC_MAC",
        "QUALIFICATION_ROOT",
        "QUALIFICATION_SOURCE_SHA",
        "QUALIFICATION_TREE_SHA",
        "QUALIFICATION_UNIT",
        "R2_BUCKET",
        "R2_ENDPOINT",
        "READINESS_HEAD_SHA",
        "READINESS_PR_NUMBER",
        "RECOVERY_REF",
        "REGRESSION_ROOT",
        "RELEASE_APP_CLIENT_ID",
        "RELEASE_APP_PRIVATE_KEY",
        "RELEASE_APP_SLUG",
        "RELEASE_ID",
        "RELEASE_RUN_ID",
        "RELEASE_TAG",
        "RELEASE_TARGET",
        "RELEASE_THEME",
        "RELEASE_VERSION",
        "RUNTIME_CONTRACT",
        "RUN_ID",
        "RUST_VERSION",
        "SHARD_ID",
        "SHARD_ROOT",
        "SOURCE_SHA",
        "SSH_PORT",
        "SUBSTRATE_CONTRACT",
        "TREE_SHA",
        "TRIGGER_EVENT",
        "TRIGGER_HEAD_BRANCH",
        "TRIGGER_HEAD_SHA",
        "TRIGGER_RUN_ID",
        "V010_PREPARED_RUNTIME_ROOT",
        "V010_PREPARED_SOURCE_ROOT",
        "V010_QUALIFICATION_RUNTIME_ROOT",
        "V010_QUALIFICATION_SOURCE_ROOT",
        "V09_BOUNDARY_END",
        "V09_BOUNDARY_START",
        "V09_FINAL_SHARD",
        "V09_PRIMARY_SHARD",
        "V09_QUALIFICATION_ROOT",
        "V09_SHARD_ID",
        "VERIFICATION_EVENT",
        "VERIFICATION_REF",
        "VERIFICATION_RUN_ID",
        "VERIFIED_SOURCE_SHA",
        "VM_ACCELERATION",
        "WORKFLOW_REF",
    )
)


def workflow_execution_context_guarded(
    workflow: str,
    *,
    data_only: bool,
    runner_labels: tuple[str, ...] = ("ubuntu-24.04", "ubuntu-latest"),
) -> bool:
    """Audit the runner and every env mapping before a shell can import it.

    Only canonical block maps with literal variable names are inspectable.
    Flow maps, whole-map expressions, aliases, nested maps and duplicate keys
    fail closed. Run/block-scalar contents remain opaque data, not YAML keys.
    """
    try:
        workflow = normalize_workflow_keys(workflow)
    except ValueError:
        return False
    scalar_indent = None
    env_indent = None
    approved_runners = {"runs-on: " + label for label in runner_labels}
    names: set[str] = set()
    for line in workflow.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if scalar_indent is not None:
            if not stripped or indent > scalar_indent:
                continue
            scalar_indent = None
        if not stripped or stripped.startswith("#"):
            continue
        if env_indent is not None and indent <= env_indent:
            if not names:
                return False
            env_indent = None
        if env_indent is not None:
            entry = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*:[ \t]*(.+)", stripped)
            if indent != env_indent + 2 or entry is None:
                return False
            name, value = entry.groups()
            if name in names or value[0] in "!&*{[":
                return False
            names.add(name)
            if name in WORKFLOW_EMPTY_STARTUP_ENV:
                if value not in {"''", '""'}:
                    return False
            elif data_only:
                if name not in TOOLCHAIN_DATA_ENV_KEYS:
                    return False
            elif (
                name in {"PATH", "CDPATH", "GLOBIGNORE", "IFS", "PS4", "BASH_XTRACEFD"}
                or name.startswith(("BASH_FUNC_", "LD_", "DYLD_", "NODE_"))
                or (
                    name.startswith("PYTHON")
                    and name != "PYTHON_WHEEL_SOURCE_DATE_EPOCH"
                )
            ):
                return False
        else:
            if re.match(r"(?:-[ \t]+)?env:", stripped):
                if stripped != "env:" and not re.fullmatch(r"env:[ \t]+#.*", stripped):
                    return False
                env_indent = indent
                names = set()
            if re.match(
                r"(?:container|services|defaults|working-directory)[ \t]*:", stripped
            ):
                return False
            if re.match(r"runs-on[ \t]*:", stripped):
                if stripped.split(" #", 1)[0] not in approved_runners:
                    return False
        if re.search(r":[ \t]*[|>][-+]?[0-9]?[ \t]*(?:#.*)?$", line):
            scalar_indent = indent
    return env_indent is None or bool(names)


def toolchain_data_loads_guarded(
    workflow: str,
    *,
    require_load: bool = False,
    workflow_name: str | None = None,
) -> bool:
    """Allow only exact, unconditional validated-data loads in reviewed steps."""
    if not workflow_execution_context_guarded(
        workflow,
        data_only=require_load,
        runner_labels=("ubuntu-24.04", "ubuntu-latest")
        if not require_load or workflow_name == ".github/workflows/codeql.yml"
        else ("ubuntu-24.04",),
    ):
        return False
    if workflow_name is not None:
        inspected = _workflow_jobs(workflow, workflow_name)
        if inspected is None:
            return False
        workflow, executable = inspected
        if not executable:
            return True
    loader = TOOLCHAIN_WORKFLOW_LOAD
    values_read = TOOLCHAIN_VALUES_READ
    exact_source_assertions = (
        '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
    )
    allowed_prefixes = {
        ("set -euo pipefail", loader),
        ("set -euo pipefail", *exact_source_assertions, loader),
    }
    lines = workflow.splitlines()
    # YAML strips scalar quotes before shell execution. Reject quoted inline
    # run values rather than treating the quoted source as inert text.
    if any(
        re.match(r"""^[ \t]*(?:-[ \t]+)?run[ \t]*:[ \t]*['"]""", line) for line in lines
    ):
        return False
    # YAML folds physical lines into executable commands. Only the reviewed
    # v0.5 Cargo test is permitted to use folded run scalars.
    reviewed_folded = (
        (
            "      - name: Run component and verifier contracts\n"
            "        run: >-\n"
            '          cargo test --locked --target-dir "$LINURA_CARGO_TARGET"\n'
            "          -p linura-provider-sdk\n"
            "          -p linura-executor-systemd\n"
            "          -p linura-linux-observation\n"
            "          -p linura-verifier-systemd"
        ),
        (
            "      - name: Produce read-only advisory shadow decision\n"
            "        if: steps.activation.outputs.shadow == 'true'\n"
            "        env:\n"
            "          GITHUB_TOKEN: ${{ github.token }}\n"
            "          HEAD_SHA: ${{ inputs.head_sha }}\n"
            "        run: >-\n"
            "          python3 tools/applicable_qualification.py decision-head\n"
            '          --repository "${{ github.repository }}"\n'
            '          --head-sha "$HEAD_SHA"\n'
            "          --token-env GITHUB_TOKEN"
        ),
    )
    folded_count = 0
    for index, line in enumerate(lines):
        if re.match(r"^[ \t]*(?:-[ \t]+)?run[ \t]*:[ \t]*>", line) is None:
            continue
        folded_count += 1
        start = index - 1
        while start >= 0 and not lines[start].startswith("      - "):
            start -= 1
        end = index + 1
        while end < len(lines) and not lines[end].startswith("      - "):
            end += 1
        if (
            folded_count > 1
            or start < 0
            or "\n".join(lines[start:end]).rstrip() not in reviewed_folded
        ):
            return False
    startup_keys = re.compile(r"\b(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS)\b")
    empty_startup = re.compile(
        r"""^[ \t]*(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS):[ \t]*(?:''|"")[ \t]*$"""
    )
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        if startup_keys.search(line) and empty_startup.fullmatch(line) is None:
            return False
        if re.match(
            r"^\s*(?:defaults|working-directory|PYTHONPATH|PYTHONHOME|PATH):",
            line,
        ):
            return False

    # Unknown sourcing, dynamic evaluation and nested shell execution are
    # outside the reviewed direct-shell contract, even with variable paths.
    source_command = re.compile(
        r"""^(?:\\?source)(?![ \t]*=)(?:[ \t]+|\$\{|\$|\\)|^(?:\\?\.)[ \t]+"""
    )
    embedded_source = re.compile(
        r"""(?:[;&|({][ \t]*|\b(?:then|do|run:|builtin|command)[ \t]+)(?:\\?source|\\?\.)[ \t]+"""
    )
    dynamic_execution = re.compile(
        r"^(?:eval\b|alias\b|(?:command[ \t]+)?(?:bash|dash|zsh|ksh|ash|mksh|sh)[ \t]+-[a-z]*c\b)"
    )

    # A script filename supplied through shell expansion can alias the
    # executable toolchain contract declared outside the run: block.
    # Reject executable variable/command-substitution and contract paths;
    # parsing-only bash -n is not executable.
    indirect_shell_execution = re.compile(
        r"""(?<![A-Za-z0-9_./-])(?:/(?:usr/)?bin/)?(?:bash|dash|zsh|ksh|ash|mksh|sh)[ \t]+
        (?!-(?:[A-Za-z]*n[A-Za-z]*)[ \t]+)
        (?:(?:-[A-Za-z]+|--)[ \t]+)*
        ["']?(?:\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)
        |tools/codex/versions\.env(?:["']|[ \t;&|)]|$)|\$\()""",
        re.VERBOSE,
    )

    def possible_source(command: str) -> bool:
        return (
            source_command.search(command) is not None
            or embedded_source.search(command) is not None
            or dynamic_execution.search(command) is not None
            or indirect_shell_execution.search(command) is not None
            or (
                "tools/codex/versions.env" in command
                and ("source" in command or " ." in command)
            )
        )

    # A YAML literal block removes indentation, then Bash removes escaped
    # physical newlines before recognizing commands. Audit that reconstructed
    # command as well as each physical line: "sour\" + "ce" is still "source".
    # Neither the reviewed data loader nor the field read uses continuation.
    direct_variable_execution = re.compile(
        r"""^(?:(?:if|elif|else|then|do|while|until|coproc)\s+|[^;#\n]*;\s*)?
        (?:(?:command|builtin|exec|env|time)\s+(?:--?\w*\s+)*|!\s+)*
        (?:[A-Za-z_]\w*=[A-Za-z0-9_.-]+\s+)*
        (?:[^\s/;=]*"[^"/\n]*\$[^"/\n]*"[^\s/;=]*
        |\$(?:\{[^}\n]+\}|[A-Za-z_]\w*)
        |\$\(|`)
        (?=$|[\s;&|)])""",
        re.VERBOSE,
    )
    audit_variables = require_load or "tools/codex/versions.env" in workflow
    for start, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        if (
            audit_variables
            and direct_variable_execution.search(line.strip())
            and (start == 0 or not lines[start - 1].endswith("\\"))
        ):
            return False
        if not line.endswith("\\"):
            continue
        # A continued argument is part of the preceding command, not a new
        # executable statement. Its full command is audited from its first line.
        if start > 0 and lines[start - 1].endswith("\\"):
            continue
        fragments: list[str] = []
        index = start
        while index < len(lines):
            physical = lines[index].strip()
            continued = physical.endswith("\\")
            fragments.append(physical[:-1] if continued else physical)
            if not continued:
                break
            index += 1
        reconstructed = "".join(fragments)
        if possible_source(reconstructed) or (
            audit_variables and direct_variable_execution.search(reconstructed)
        ):
            return False

    sources = {
        i
        for i, line in enumerate(lines)
        if (
            (
                possible_source(line.strip())
                or line.strip() == values_read
                or line.strip() == TOOLCHAIN_WORKFLOW_VALIDATE
            )
            and not line.lstrip().startswith("#")
        )
    }
    # YAML shorthand steps can execute the toolchain before a guarded load.
    # Only reviewed named steps with the exact validator/source sequence are
    # permitted. Inspect shorthand multiline bodies as well as inline values.
    for index, line in enumerate(lines):
        if re.match(r"^[ ]*-[ ]+run[ ]*:", line):
            indent = len(line) - len(line.lstrip())
            block = [line]
            for following in lines[index + 1 :]:
                if (
                    following.strip()
                    and len(following) - len(following.lstrip()) <= indent
                ):
                    break
                block.append(following)
            if any(
                "tools/codex/versions.env" in statement
                or possible_source(statement.strip())
                for statement in block
                if not statement.lstrip().startswith("#")
            ):
                return False
    # Also reject direct contract use in named inline shell steps at any
    # indentation, rather than assuming a fixed workflow layout.
    if any(
        re.match(r"^[ ]*(?:-[ ]+)?run[ ]*:", line)
        and "tools/codex/versions.env" in line
        for line in lines
    ):
        return False
    if not sources and require_load:
        return False
    matched: set[int] = set()
    for i, line in enumerate(lines):
        if re.fullmatch(r"        run: [>|][-+]?(?:[ \t]+#.*)?", line) is None:
            continue
        beginning = i + 1
        ending = beginning
        while ending < len(lines):
            candidate = lines[ending]
            if candidate.strip() and not candidate.startswith("          "):
                break
            ending += 1
        code = [
            (number, lines[number].strip())
            for number in range(beginning, ending)
            if lines[number].strip() and not lines[number].lstrip().startswith("#")
        ]
        run_sources = [
            (pos, number) for pos, (number, _) in enumerate(code) if number in sources
        ]
        if line != "        run: |" and (
            run_sources
            or any("tools/codex/versions.env" in command for _, command in code)
        ):
            return False
        # Unreviewed executable references to the contract are not validators.
        # This also catches calls that hide sourcing behind an opaque function.
        if any(
            "tools/codex/versions.env" in command
            and command not in {loader, TOOLCHAIN_WORKFLOW_VALIDATE}
            for _, command in code
        ):
            return False
        if not run_sources:
            continue
        # The actual step cannot have an if guard, ignored failure, or
        # non-Bash shell. Check metadata before AND after the run block.
        step_start = i - 1
        while step_start >= 0 and not lines[step_start].startswith("      - "):
            step_start -= 1
        if step_start < 0:
            return False
        if not toolchain_load_follows_checkout(lines, step_start, workflow_name):
            return False
        step_end = ending
        while step_end < len(lines) and not lines[step_end].startswith("      - "):
            step_end += 1
        metadata = [
            value.strip()
            for value in lines[step_start:step_end]
            if value.startswith("        ") and not value.startswith("          ")
        ]
        if (
            not lines[step_start].startswith("      - name: ")
            or metadata.count("run: |") != 1
            or metadata.count("shell: bash") > 1
            or metadata.count("id: toolchain_data") != 1
            or any(
                value not in {"run: |", "shell: bash", "id: toolchain_data"}
                for value in metadata
            )
        ):
            return False
        if tuple(command for _, command in code) in {
            ("set -euo pipefail", TOOLCHAIN_WORKFLOW_VALIDATE),
            (
                "set -euo pipefail",
                'test "$GITHUB_REF" = refs/heads/main',
                'test "$GITHUB_SHA" = "$SOURCE_SHA"',
                'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
                TOOLCHAIN_WORKFLOW_VALIDATE,
            ),
        }:
            matched.add(code[-1][0])
            continue
        for pos, number in run_sources:
            if lines[number] != "          " + values_read:
                return False
            prefix = tuple(command for _, command in code[:pos])
            if prefix not in allowed_prefixes:
                return False
            if lines[code[pos - 1][0]] != "          " + loader:
                return False
            if (
                pos + 1 >= len(code)
                or code[pos + 1][1] != TOOLCHAIN_VALUES_NONEMPTY
                or lines[code[pos + 1][0]] != "          " + TOOLCHAIN_VALUES_NONEMPTY
            ):
                return False
            matched.add(number)
    if require_load:
        step_sections = [
            index for index, value in enumerate(lines) if value == "    steps:"
        ]
        if not step_sections:
            return False
        for index in step_sections:
            ending = index + 1
            while ending < len(lines):
                value = lines[ending]
                if value.strip() and len(value) - len(value.lstrip()) <= 4:
                    break
                ending += 1
            if not any(index < number < ending for number in matched):
                return False
    return matched == sources


def check(root: Path = ROOT) -> list[str]:
    failures = []
    # Cache only this invocation's input snapshot. A later check must reread
    # every input so adversarial mutations cannot reuse a prior verdict.
    inputs: dict[str, str] = {}

    def require(value: bool, reason: str) -> None:
        if not value:
            failures.append(reason)

    # No package initializer may execute before the isolated validator.
    require(
        not (root / "tools/__init__.py").exists(),
        "tools package initializer must not run before toolchain validation",
    )

    def read(name: str) -> str:
        if name in inputs:
            return inputs[name]
        path = root / name
        if not path.is_file() or path.is_symlink():
            failures.append("missing or unsafe gate input: " + name)
            return ""
        try:
            content = path.read_text(encoding="utf-8")
            if name.startswith(".github/workflows/"):
                try:
                    content = normalize_workflow_keys(content)
                except ValueError as exc:
                    failures.append(
                        "unsafe workflow mapping syntax: " + name + ": " + str(exc)
                    )
                    return ""
            inputs[name] = content
            return content
        except (OSError, UnicodeError):
            failures.append("unreadable gate input: " + name)
            return ""

    mandatory_bodies: dict[str, tuple[str, int] | None] = {}
    for job, path in MANDATORY.items():
        source = read(path)
        # CodeQL has no toolchain-data step, but its native merge-authority
        # job still cannot inherit interpreter selectors or replacement hosts.
        # Keep its existing ubuntu-latest runner; loader jobs require 24.04.
        if job == "analyze":
            require(
                workflow_execution_context_guarded(
                    source,
                    data_only=True,
                    runner_labels=("ubuntu-latest",),
                ),
                "analyze: unreviewed workflow execution context",
            )
        events = section(source, "on")
        require(events is not None, job + ": missing event map")
        pr = section(events or "", "pull_request", 2)
        push = section(events or "", "push", 2)
        # A mandatory native gate must not silently disappear for particular
        # target branches, PR events, or paths. Keep pull_request unqualified:
        # GitHub's default opened/reopened/synchronize events are intentional.
        # A bare pull_request event has no non-comment children at any YAML
        # indentation. Anchoring on four spaces permits valid deeper filters.
        require(
            pr is not None
            and all(
                not line.strip() or line.lstrip().startswith("#")
                for line in pr.splitlines()
            ),
            job + ": must run on every PR without branch, type, or path filters",
        )
        require(
            push is not None
            and re.search(r"(?m)^    branches: \[main\]\s*$", push or "") is not None
            and not re.search(
                r"(?m)^    (paths|paths-ignore|branches-ignore):", push or ""
            ),
            job + ": must run on every main push",
        )
        if job in ("dependency-audit", "analyze"):
            # Independent scheduled scans detect new advisories even when idle.
            expected = "17 4 * * 1" if job == "dependency-audit" else "41 3 * * 3"
            schedule = section(events or "", "schedule", 2)
            entries = [
                line.strip() for line in (schedule or "").splitlines() if line.strip()
            ]
            require(
                entries == [f'- cron: "{expected}"'],
                job + ": must retain reviewed independent weekly scheduled scan",
            )
        jobs = section(source, "jobs")
        required_job = section(jobs or "", job, 2)
        require(required_job is not None, job + ": native check job removed")
        # Valid YAML may indent direct job properties six (or more) spaces.
        # Anchor all skip/dependency guards at the actual mapping indentation.
        runner = re.search(r"(?m)^( +)runs-on:", required_job or "")
        job_indent = len(runner.group(1)) if runner else 0
        mandatory_bodies[job] = (
            (required_job, job_indent)
            if required_job is not None and job_indent
            else None
        )
        require(
            required_job is not None
            and job_indent > 2
            and re.search(
                r"(?m)^ {" + str(job_indent) + r"}(?:if|needs|continue-on-error):",
                required_job or "",
            )
            is None,
            job + ": mandatory job must be unconditional and independent",
        )
        # Required checks must analyze the triggering GitHub revision, not an
        # independently selected branch. A second checkout could replace the
        # source after an initially correct checkout, so allow exactly one.
        require(
            checkout_is_triggering_revision(required_job or "", job_indent),
            job + ": must checkout triggering revision without a ref override",
        )
        require("continue-on-error:" not in source, job + ": fail-open flag prohibited")
        # Inherited workflow/job shells can exit successfully without running
        # an otherwise exact mandatory command. No run defaults are needed here.
        require(
            re.search(r"(?m)^[ \t]*defaults\s*:", source) is None,
            job + ": run defaults may bypass mandatory executable steps",
        )

    ci = read(MANDATORY["canonical-check"])
    xtask = read("tools/xtask/src/main.rs")
    require(
        hashlib.sha256(read("tools/run_tooling_tests.py").encode("utf-8")).hexdigest()
        == REVIEWED_TOOLING_RUNNER_SHA256,
        "canonical Python tooling runner source changed",
    )
    canonical = mandatory_bodies.get("canonical-check")
    if canonical:
        body, indent = canonical
        # No job-level container, alternate runner, service, custom strategy,
        # privilege or environment escape hatch may precede the suite.
        # An untrusted container can replace every absolute system binary
        # before pinned checkout/setup-node even begin.
        direct_properties = [
            line
            for line in body.splitlines()
            if line.strip()
            and line.startswith(" " * indent)
            and not line.startswith(" " * (indent + 1))
            and not line.lstrip().startswith("#")
        ]
        require(
            direct_properties
            == [
                " " * indent + "runs-on: ubuntu-24.04",
                " " * indent + "steps:",
            ],
            "canonical CI publisher job must use exact trusted hosted runner"
            " without container or alternate job configuration",
        )
        for label, command in (
            ("Run canonical Linura checks", "cargo xtask check"),
            ("Verify canonical crates.io package", "cargo package --locked -p linura"),
            (
                "Verify canonical PyPI package",
                "PYTHONPATH=bindings/python/src python3 -m unittest discover",
            ),
        ):
            step = workflow_step(body, indent, "name", label)
            prop_indent = indent + 4
            run = re.search(r"(?m)^ {" + str(prop_indent) + r"}run: (.+)$", step or "")
            actual = run.group(1).strip() if run else ""
            if label == "Verify canonical PyPI package":
                # Protect the whole approved shell block. A substring check
                # accepts early exits, disabled tests and skipped wheel imports.
                marker = " " * prop_indent + "run: |"
                lines = (step or "").splitlines()
                actual_commands = (
                    [
                        line.strip()
                        for line in lines[lines.index(marker) + 1 :]
                        if line.strip()
                    ]
                    if marker in lines
                    else []
                )
                executable = (
                    actual == "|"
                    and tuple(actual_commands) == PYPI_VERIFICATION_COMMANDS
                )
            else:
                executable = actual == command
            # A step-level SHELLOPTS/BASH_ENV mapping can render an exact
            # reviewed command a no-op. These three native gate steps have
            # no approved environment override; reject every step-level env.
            injected_env = re.search(
                r"(?m)^ {" + str(prop_indent) + r"}env\s*:", step or ""
            )
            require(
                step_is_unconditional(step, indent)
                and injected_env is None
                and executable,
                "canonical CI missing unconditional executable step: " + label,
            )
    load_contract = (
        workflow_step(
            canonical[0], canonical[1], "name", "Load repository toolchain contract"
        )
        if canonical
        else None
    )
    require(
        load_contract is not None
        and toolchain_data_loads_guarded(ci, require_load=True),
        "canonical CI must validate toolchain data loading",
    )
    failures.extend(local_shell_sources_guarded(root))
    workflow_files = sorted((root / ".github/workflows").glob("*.y*ml"))
    workflow_names = {path.relative_to(root).as_posix() for path in workflow_files}
    for relative in TOOLCHAIN_DATA_WORKFLOWS:
        require(relative in workflow_names, relative + ": required workflow is missing")
    reusable_edges: dict[str, tuple[str, ...]] = {}
    for workflow_file in workflow_files:
        relative = workflow_file.relative_to(root).as_posix()
        source = read(relative)
        guarded = toolchain_data_loads_guarded(
            source, require_load=True, workflow_name=relative
        )
        require(guarded, relative + ": unguarded workflow job execution")
        if relative in TOOLCHAIN_DATA_WORKFLOWS:
            require(
                guarded,
                relative
                + ": unsafe toolchain execution or missing validated data load",
            )
        targets = tuple(
            target[2:]
            for target in re.findall(
                r"(?m)^    uses: (\./\.github/workflows/\S+)$", source
            )
        )
        reusable_edges[relative] = targets
        for target in targets:
            require(
                target in workflow_names
                and section(section(read(target), "on") or "", "workflow_call", 2)
                is not None,
                relative + ": reusable workflow target is missing or not callable",
            )

    visiting: set[str] = set()
    finished: set[str] = set()

    def acyclic(name: str) -> bool:
        if name in visiting:
            return False
        if name in finished:
            return True
        visiting.add(name)
        result = all(acyclic(target) for target in reusable_edges.get(name, ()))
        visiting.remove(name)
        finished.add(name)
        return result

    require(
        all(acyclic(name) for name in reusable_edges),
        "reusable workflow graph must be acyclic",
    )
    # There is no reviewed workflow- or job-level environment mapping in
    # canonical CI. Such mappings can inject readonly Bash startup flags
    # (SHELLOPTS=noexec) across otherwise exact native qualification commands.
    # The publisher's protected step also runs this policy checker itself,
    # after clearing shell startup variables, before any Node test invocation.
    require(
        re.search(r"(?m)^(?:env|    env)\s*:", ci) is None,
        "canonical CI may not inherit workflow/job environment variables",
    )
    # Publisher source is a separate merge authority, so its Node security
    # suite must remain in the unfiltered native CI gate. A path-filtered
    # publisher workflow cannot defend a PR editing only canonical CI.
    if canonical:
        body, indent = canonical
        reviewed_node = (
            "      - name: Install pinned Node runtime for trusted publisher tests\n"
            "        uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0\n"
            "        with:\n"
            "          node-version: '22.23.3'\n"
        )
        reviewed_tests = (
            "      - name: Validate trusted qualification publisher in canonical CI\n"
            "        env:\n"
            "          NODE_OPTIONS: ''\n"
            "          BASH_ENV: ''\n"
            "          ENV: ''\n"
            "          SHELLOPTS: ''\n"
            "          BASHOPTS: ''\n"
            "        shell: /usr/bin/bash --noprofile --norc -euo pipefail {0}\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          if [ -e tools/__init__.py ] || [ -L tools/__init__.py ]; then\n"
            "            printf '%s\\n' 'unsafe tools package initializer' >&2\n"
            "            exit 1\n"
            "          fi\n"
            "          /usr/bin/python3 -I -S - <<'PY'\n"
            "          import hashlib\n"
            "          import os\n"
            "          from pathlib import Path\n"
            "          import re\n"
            "          import subprocess\n"
            "          \n"
            "          def deny(message):\n"
            '              raise SystemExit("publisher source provenance denied: " + message)\n'
            "          \n"
            '          sha = os.environ.get("GITHUB_SHA", "")\n'
            '          if not re.fullmatch(r"[0-9a-f]{40}", sha):\n'
            '              deny("invalid triggering SHA")\n'
            '          git_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",\n'
            '                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",\n'
            '                     "GIT_NO_REPLACE_OBJECTS": "1"}\n'
            "          \n"
            "          def git(*args):\n"
            '              result = subprocess.run(["/usr/bin/git", *args], env=git_env,\n'
            "                                      check=False, stdout=subprocess.PIPE,\n"
            "                                      stderr=subprocess.DEVNULL, timeout=20)\n"
            "              if result.returncode:\n"
            '                  deny("cannot read source commit")\n'
            "              return result.stdout\n"
            "          \n"
            '          if git("rev-parse", "--verify", "HEAD^{commit}").strip().decode("ascii") != sha:\n'
            '              deny("checkout is not the triggering revision")\n'
            '          scopes = (".github/workflows/ci.yml", "tools/check_validation_gates.py",\n'
            '                    "tests/tooling/test_validation_gates.py", "services/qualification-publisher")\n'
            '          raw_tree = git("ls-tree", "-r", "-z", "--full-tree", sha, "--", *scopes)\n'
            "          expected = {}\n"
            '          for item in raw_tree.split(b"\\x00"):\n'
            "              if not item:\n"
            "                  continue\n"
            "              try:\n"
            '                  info, path = item.split(b"\\t", 1)\n'
            '                  mode, kind, digest = info.split(b" ")\n'
            '                  name = path.decode("utf-8")\n'
            "              except (ValueError, UnicodeDecodeError):\n"
            '                  deny("malformed source tree")\n'
            '              if (mode not in (b"100644", b"100755") or kind != b"blob"\n'
            '                      or not re.fullmatch(rb"[0-9a-f]{40}", digest)\n'
            "                      or name in expected):\n"
            '                  deny("unsafe source tree entry")\n'
            '              expected[name] = digest.decode("ascii")\n'
            "          root = Path.cwd()\n"
            "          seen = set()\n"
            "          def visit(path):\n"
            "              if path.is_symlink():\n"
            '                  deny("source symlink")\n'
            "              if path.is_dir():\n"
            "                  for entry in path.iterdir():\n"
            "                      visit(entry)\n"
            "              elif path.is_file():\n"
            "                  relative = path.relative_to(root).as_posix()\n"
            "                  if relative not in expected:\n"
            '                      deny("unexpected source file")\n'
            "                  data = path.read_bytes()\n"
            '                  actual = hashlib.sha1(b"blob " + str(len(data)).encode("ascii")\n'
            '                                        + b"\\x00" + data).hexdigest()\n'
            "                  if actual != expected[relative]:\n"
            '                      deny("source differs from triggering commit")\n'
            "                  seen.add(relative)\n"
            "              else:\n"
            '                  deny("missing or special source entry")\n'
            "          for scope in scopes:\n"
            "              path = root / scope\n"
            "              if not path.exists() and not path.is_symlink():\n"
            '                  deny("missing protected source")\n'
            "              visit(path)\n"
            "          if seen != set(expected) or len(seen) < 6:\n"
            '              deny("incomplete protected source inventory")\n'
            '          print("publisher tests bound to triggering source SHA")\n'
            "          PY\n"
            "          /usr/bin/python3 -I -S tools/check_validation_gates.py\n"
            '          test "$(/usr/bin/env -i PATH="$PATH" LANG=C.UTF-8 node --version)" = \'v22.23.3\'\n'
            '          /usr/bin/env -i PATH="$PATH" LANG=C.UTF-8 node --check services/qualification-publisher/publisher.mjs\n'
            '          /usr/bin/env -i PATH="$PATH" LANG=C.UTF-8 node --check services/qualification-publisher/server.mjs\n'
            '          /usr/bin/env -i PATH="$PATH" LANG=C.UTF-8 node --test services/qualification-publisher/test/*.test.mjs\n'
        )
        for label, expected in (
            ("Install pinned Node runtime for trusted publisher tests", reviewed_node),
            (
                "Validate trusted qualification publisher in canonical CI",
                reviewed_tests,
            ),
        ):
            step = workflow_step(body, indent, "name", label)
            require(
                step_is_unconditional(
                    step,
                    indent,
                    allow_reviewed_shell=(
                        label
                        == "Validate trusted qualification publisher in canonical CI"
                    ),
                )
                and (step or "").strip() == expected.strip(),
                "canonical CI missing mandatory publisher authority step: " + label,
            )
        # Pre-test repository code can use sudo on GitHub's ubuntu-24.04
        # runner to overwrite even absolute system binaries. Only the
        # immutable checkout and setup-node actions may precede this suite.
        reviewed_checkout = (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
            "        with:\n"
            "          fetch-depth: 0\n"
        )
        checkout_step = workflow_step(
            body,
            indent,
            "uses",
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        require(
            step_is_unconditional(checkout_step, indent)
            and (checkout_step or "").strip() == reviewed_checkout.strip(),
            "canonical CI publisher checkout must use exact pinned configuration",
        )
        steps_body = section(body, "steps", indent) or ""
        step_indent = indent + 2
        all_headers = re.findall(
            r"(?m)^ {" + str(step_indent) + r"}-[ \t]+[^\r\n]+$",
            steps_body,
        )
        headers = re.findall(
            r"(?m)^ {" + str(step_indent) + r"}- (?:name|uses|run):[^\r\n]*$",
            steps_body,
        )
        checkout_header = " " * step_indent + (
            "- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
        )
        setup_header = (
            " " * step_indent
            + "- name: Install pinned Node runtime for trusted publisher tests"
        )
        test_header = (
            " " * step_indent
            + "- name: Validate trusted qualification publisher in canonical CI"
        )
        require(
            len(headers) == len(all_headers)
            and headers[:3] == [checkout_header, setup_header, test_header]
            and headers.count(checkout_header) == 1
            and headers.count(setup_header) == 1
            and headers.count(test_header) == 1,
            "canonical CI must run publisher tests immediately after pinned Node setup"
            " and checkout, before any untrusted executable step",
        )
    check_entry = "fn check() -> Result<(), String> {\n"
    pieces = xtask.split(check_entry)
    actual_body = (
        pieces[1].split("\n}\n")[0] + "\n"
        if len(pieces) == 2 and "\n}\n" in pieces[1]
        else None
    )
    require(
        actual_body == XTASK_CHECK_BODY and '"check" => check(),' in xtask,
        "canonical xtask execution sequence changed",
    )

    security = read(MANDATORY["dependency-audit"])
    pins = read("tools/codex/versions.env")
    require(
        re.search(r"(?m)^CARGO_AUDIT_VERSION=\d+\.\d+\.\d+$", pins) is not None,
        "cargo-audit exact version pin removed",
    )
    for token in (
        'cargo install cargo-audit --locked --version "$CARGO_AUDIT_VERSION"',
        'test "$actual_version" = "$CARGO_AUDIT_VERSION"',
        '"$HOME/.cargo/bin/cargo-audit" audit',
    ):
        require(token in security, "security audit missing " + token)
    security_gate = mandatory_bodies.get("dependency-audit")
    if security_gate:
        body, indent = security_gate
        audit_step = workflow_step(body, indent, "name", "Audit Rust dependencies")
        # Pin the entire reviewed executable block, not merely the presence
        # of the audit command. A shell-level condition, exit, or wrapper
        # must not make the mandatory step pass without running cargo-audit.
        marker = " " * (indent + 4) + "run: |"
        lines = (audit_step or "").splitlines()
        commands = (
            [line.strip() for line in lines[lines.index(marker) + 1 :] if line.strip()]
            if marker in lines
            else []
        )
        require(
            step_is_unconditional(audit_step, indent)
            and commands
            == [
                "set -euo pipefail",
                '"$HOME/.cargo/bin/cargo-audit" audit',
            ],
            "security audit must run unconditionally",
        )
    for forbidden in ("|| true", "continue-on-error:", "--ignore", "--no-fail"):
        require(
            forbidden not in security, "security audit may be bypassed: " + forbidden
        )

    codeql_gate = mandatory_bodies.get("analyze")
    if codeql_gate:
        body, indent = codeql_gate
        action_revisions = {}
        for action in ("github/codeql-action/init@", "github/codeql-action/analyze@"):
            step = workflow_step(body, indent, "uses", action)
            pinned = re.search(
                r"(?m)^ {"
                + str(indent + 2)
                + r"}- uses: "
                + re.escape(action)
                + r"([0-9a-f]{40})(?:\s+#.*)?$",
                step or "",
            )
            require(
                step_is_unconditional(step, indent) and pinned is not None,
                "CodeQL missing unconditional SHA-pinned action: " + action,
            )
            if pinned is not None:
                action_revisions[action] = pinned.group(1)
            if action.endswith("/init@"):
                settings = section(step or "", "with", indent + 4)
                # Match the entire setting block. A comment, duplicate YAML
                # key, missing language or a different extraction mode must not
                # satisfy the required source-analysis coverage.
                require(
                    settings is not None
                    and re.fullmatch(
                        r"\s*languages: rust,javascript-typescript,c-cpp,python\s*\n"
                        r"\s*build-mode: none\s*",
                        settings,
                    )
                    is not None,
                    "CodeQL initialization must configure exactly Rust, JavaScript, C/C++ and Python with build-mode none",
                )
        require(
            len(action_revisions) == 2 and len(set(action_revisions.values())) == 1,
            "CodeQL init/analyze actions must share the same immutable revision",
        )
    codex = read(SPECIALIZED["codex"][0])
    require(
        workflow_execution_context_guarded(
            codex, data_only=True, runner_labels=("ubuntu-24.04",)
        ),
        "codex: unreviewed workflow execution context",
    )
    # Workflow- and job-level run defaults override the effective shell of
    # every otherwise reviewed command. Ban inherited defaults, including
    # inline YAML mappings, so a successful no-op shell cannot fake evidence.
    require(
        re.search(r"(?m)^[ \t]*defaults\s*:", codex) is None,
        "codex: inherited run defaults may bypass required steps",
    )
    codex_jobs = section(codex, "jobs") or ""
    codex_job = section(codex_jobs, "fresh-environment", 2)
    # The test module imports tools before setup/preflight run. Keep this
    # initializer rejection independent of imports and preceding every test.
    prebootstrap_tests = workflow_step(
        codex_job or "", 4, "name", "Verify validation-gate tests before bootstrap"
    )
    require(
        step_is_unconditional(prebootstrap_tests, 4)
        and executable_run_block(prebootstrap_tests, 4)
        == (
            "set -euo pipefail",
            "if [ -e tools/__init__.py ] || [ -L tools/__init__.py ]; then",
            "  printf '%s\\n' 'unsafe tools package initializer' >&2",
            "  exit 1",
            "fi",
            "python3 -m unittest discover -s tests/tooling -p 'test_validation_gates.py' \\",
            "  -k reviewed_local_contract_loads \\",
            "  -k transitive_local_shell_sourcing \\",
            "  -k dynamic_shell \\",
            "  -k toolchain_preload \\",
            "  -k composite_action_cannot_hide_contract_source \\",
            "  -k checked_in_contract \\",
            "  -k fixture_contract \\",
            "  -k validation_gate_tests_run_before_heavy_bootstrap",
        ),
        "codex: pre-import tooling guard missing or modified",
    )
    # An unconditional job is insufficient: each required step must execute,
    # rather than leaving its command as dead text in the workflow.
    for label, tokens in CODEX_REQUIRED_STEPS:
        step = workflow_step(codex_job or "", 4, "name", label)
        require(
            step_is_unconditional(step, 4)
            and re.search(r"(?m)^        run: (?:\||[^\n]+)$", step or "") is not None
            and all(token in (step or "") for token in tokens),
            "Codex required step must execute: " + label,
        )
    for label, expected in CODEX_OTHER_EXECUTION_CONTRACTS.items():
        step = workflow_step(codex_job or "", 4, "name", label)
        direct_run = re.search(r"(?m)^        run: (.+)$", step or "")
        run = direct_run.group(1).strip() if direct_run else ""
        executable = (
            run == "|" and executable_run_block(step, 4) == expected
            if isinstance(expected, tuple)
            else run == expected
        )
        require(
            step_is_unconditional(step, 4) and executable,
            "Codex required step must match reviewed executable content: " + label,
        )
    require(
        checkout_is_triggering_revision(codex_job or "", 4),
        "codex: must checkout triggering revision without a ref override",
    )
    injection = workflow_step(
        codex_job or "",
        4,
        "name",
        "Inject stale bindings distribution before maintenance",
    )
    require(
        step_is_unconditional(injection, 4)
        and executable_run_block(injection, 4) == CODEX_CONTAMINATION_COMMANDS,
        "Codex contamination injection must execute the complete reviewed shell block",
    )
    verification = workflow_step(
        codex_job or "", 4, "name", "Verify from a separate task process"
    )
    lines = (verification or "").splitlines()
    marker = "        run: |"
    verification_commands = (
        tuple(line.strip() for line in lines[lines.index(marker) + 1 :] if line.strip())
        if marker in lines
        else ()
    )
    require(
        verification_commands
        == (
            "set -euo pipefail",
            "PATH=/usr/bin:/bin bash scripts/preflight_codex_environment.sh --full",
            "PATH=/usr/bin:/bin bash scripts/run_codex.sh cargo --version",
            '"$HOME/.local/linura-tools/python/bin/python3" -m pip wheel \\',
            "--disable-pip-version-check --no-index --no-deps --no-build-isolation \\",
            '--wheel-dir "$RUNNER_TEMP/linura-python-wheel" ./bindings/python',
            "PYTHONPATH=bindings/python/src python3 -m unittest discover \\",
            "-s bindings/python/tests -p 'test_*.py'",
        ),
        "Codex verification must execute the complete reviewed task-time gate",
    )

    for name, (workflow, critical_paths) in SPECIALIZED.items():
        text = read(workflow)
        # A workflow-level shell default can turn an otherwise protected
        # command into a successful no-op. Keep every specialty fail-closed.
        require(
            re.search(r"(?m)^[ \t]*defaults\s*:", text) is None,
            name + ": inherited run defaults may bypass qualification",
        )
        events = section(text, "on")
        pr = section(events or "", "pull_request", 2)
        require(pr is not None, name + ": specialized PR event removed")
        # Path-scoped qualification must still run for any target branch and
        # every default PR synchronization event. Explicit branch/type filters
        # and paths-ignore can silently defeat even correctly mapped paths.
        pr_keys = re.findall(r"(?m)^    ([A-Za-z_][\w-]*):", pr or "")
        require(
            pr is not None and pr_keys == ["paths"],
            name + ": specialized PR event may contain only paths",
        )
        filters = section(pr or "", "paths", 4)
        patterns = re.findall(r"(?m)^      - [\"']([^\"']+)[\"']\s*$", filters or "")
        require(
            bool(patterns) and len(patterns) == len(set(patterns)),
            name + ": missing or duplicated path filters",
        )
        require(
            all(pattern != "!" for pattern in patterns),
            name + ": empty negative PR filter",
        )
        require(
            any(not pattern.startswith("!") for pattern in patterns),
            name + ": specialized PR triggers must include a positive path",
        )
        require(
            path_selected(workflow, patterns),
            name + ": missing critical PR trigger: " + workflow,
        )
        for path in critical_paths:
            require(
                (root / path).is_file(), name + ": missing critical source: " + path
            )
            require(
                path_selected(path, patterns),
                name + ": missing critical PR trigger: " + path,
            )
        if name in ("codex", "evidence-publication"):
            push = section(events or "", "push", 2)
            push_keys = re.findall(r"(?m)^    ([A-Za-z_][\w-]*):", push or "")
            require(
                push is not None
                and push_keys == ["branches", "paths"]
                and re.search(r"(?m)^    branches: \[main\]\s*$", push or "")
                is not None,
                name + ": main-push trigger must target main with scoped paths",
            )
            push_paths = section(push or "", "paths", 4)
            push_patterns = re.findall(
                r"(?m)^      - [\"']([^\"']+)[\"']\s*$", push_paths or ""
            )
            require(
                bool(push_patterns)
                and len(push_patterns) == len(set(push_patterns))
                and path_selected(workflow, push_patterns)
                and all(path_selected(path, push_patterns) for path in critical_paths),
                name + ": main-push routing must cover critical sources",
            )
        jobs = section(text, "jobs") or ""
        for required_job in SPECIALIZED_REQUIRED_JOBS[name]:
            job_body = section(jobs, required_job, 2)
            # Derive the actual direct-property indentation instead of assuming
            # a fixed YAML layout. Nested step conditions are not job guards.
            mapping = re.search(
                r"(?m)^( +)(?:runs-on|uses|needs|name):", job_body or ""
            )
            indent = len(mapping.group(1)) if mapping else 0
            require(
                job_body is not None
                and indent > 2
                and re.search(
                    r"(?m)^ {" + str(indent) + r"}(?:if|continue-on-error):",
                    job_body or "",
                )
                is None,
                name
                + ": required qualification job cannot be skipped: "
                + required_job,
            )
            # Only the v0.9 contract depends on another required entry job.
            # Any other needs edge can silently skip qualification if its
            # prerequisite is skipped under GitHub's default success guard.
            approved_needs = (
                ["scope"] if name == "v09" and required_job == "contract" else []
            )
            declared_needs = re.findall(
                r"(?m)^ {" + str(indent) + r"}needs:\s*(.*?)\s*$",
                job_body or "",
            )
            require(
                declared_needs == approved_needs,
                name
                + ": required qualification job has unapproved dependencies: "
                + required_job,
            )
            require(
                protected_step_guards(
                    job_body or "",
                    indent,
                    REVIEWED_STEP_CONDITIONS.get((name, required_job), {}),
                ),
                name
                + ": required qualification step guard may bypass execution: "
                + required_job,
            )
            # A protected job may not inherit a replacement run shell either.
            require(
                re.search(r"(?m)^ {" + str(indent) + r"}defaults\s*:", job_body or "")
                is None,
                name
                + ": inherited run defaults may bypass qualification: "
                + required_job,
            )
            # Explicit bash is already used by the v0.7/v0.8 lanes. Arbitrary
            # step shells could suppress tests even without inherited defaults.
            declared_shells = re.findall(
                r"(?m)^ {" + str(indent + 4) + r"}shell:[ \t]*([^\r\n]*)$",
                job_body or "",
            )
            require(
                all(
                    re.fullmatch(r"bash(?:[ \t]+#.*)?", shell.strip()) is not None
                    for shell in declared_shells
                ),
                name
                + ": unapproved step shell may bypass qualification: "
                + required_job,
            )

        if name == "evidence-publication":
            # Path routing and job presence are insufficient if the check
            # itself can be turned into a passing no-op. Pin this credential-
            # boundary's source checkout and its exact executable test step.
            verify = section(jobs, "verify", 2) or ""
            checkout = workflow_step(verify, 4, "uses", "actions/checkout@")
            require(
                checkout is not None
                and len(re.findall(r"(?m)^[ ]{6}- uses: actions/checkout@", verify))
                == 1
                and step_is_unconditional(checkout, 4)
                and re.search(
                    r"(?m)^      - uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
                    checkout,
                )
                is not None
                and re.findall(r"(?m)^        with:\s*$", checkout) == ["        with:"]
                and re.findall(r"(?m)^          [^\s].*$", checkout)
                == ["          persist-credentials: false"],
                "evidence-publication: required verified-source checkout missing or weakened",
            )
            step_name = "Test admission, provenance, privacy and R2 publishing behavior"
            verification = workflow_step(verify, 4, "name", step_name)
            command = "python3 -m unittest -v tests.tooling.test_evidence_publication"
            require(
                verification is not None
                and len(
                    re.findall(
                        r"(?m)^      - name: " + re.escape(step_name) + "$", verify
                    )
                )
                == 1
                and step_is_unconditional(verification, 4)
                and re.findall(r"(?m)^        run: (.*)$", verification) == [command],
                "evidence-publication: required test execution missing or weakened",
            )

        for path in GUIDANCE_EXCLUSIONS.get(name, ()):
            require(
                not path_selected(path, patterns),
                name + ": guidance-only change triggers machine qualification: " + path,
            )

    v09 = read(SPECIALIZED["v09"][0])
    routing_contract = read("contracts/v09-qualification-routing.toml")
    try:
        contract = tomllib.loads(routing_contract)
        require(
            contract.get("schema_version") == 1
            and contract.get("guidance_only_basenames") == ["AGENTS.md", "README.md"],
            "v0.9: invalid routing contract",
        )
        events = section(v09, "on") or ""
        pr = section(events, "pull_request", 2) or ""
        filters = section(pr, "paths", 4) or ""
        patterns = re.findall(r'(?m)^      - "([^"]+)"', filters)
        # Pin every reviewed exact input independently from the mutable
        # contract so a route cannot delete itself from both classification
        # and validation in one edit.
        for required in V09_REQUIRED_FULL_EXACT:
            require(
                required in contract["full_exact"],
                "v0.9: missing required full-qualification exact input: " + required,
            )
        for guard in V09_ROUTING_GUARD_EXACT:
            require(
                guard in contract["full_exact"],
                "v0.9: missing required routing guard full qualification: " + guard,
            )
        for harness in (
            "tools/acceptance.py",
            "scripts/qualification/v09-adversarial-guest.sh",
        ):
            require(
                harness in contract["full_exact"],
                "v0.9: missing required full-qualification harness: " + harness,
            )
        for required in (".cargo/config", ".cargo/config.toml"):
            require(
                required in contract["full_exact"],
                "v0.9: missing required full-qualification toolchain: " + required,
            )
        require(
            "packaging/wireplumber/linura-session-audio.lua" in contract["full_exact"],
            "v0.9: missing embedded audio helper qualification input",
        )
        # The reviewed full-impact prefix set is a security contract, not a
        # self-describing allowlist. A contract edit cannot delete a route and
        # thereby make the validator forget that the route was mandatory.
        for prefix in V09_REQUIRED_FULL_PREFIXES:
            require(
                prefix in contract["full_prefixes"],
                "v0.9: missing required full-qualification prefix: " + prefix,
            )
        for path in contract["full_exact"]:
            require(
                path_selected(path, patterns),
                "v0.9: untriggered full-qualification path: " + path,
            )
        for prefix in contract["full_prefixes"]:
            require(
                path_selected(prefix + "__routing-probe__.rs", patterns),
                "v0.9: untriggered full-qualification prefix: " + prefix,
            )
    except (ValueError, KeyError, TypeError) as error:
        require(False, "v0.9: invalid routing contract: " + str(error))
    require(
        v09_classifier_connected(v09),
        "v0.9: shared qualification classifier disconnected",
    )
    require(
        v09_lane_job_graph_connected(v09),
        "v0.9: qualification lane job graph disconnected",
    )
    require(
        'if [[ "$GITHUB_EVENT_NAME" != "pull_request" ]]; then' in v09
        and "full_qualification=true" in v09
        and "full_qualification != 'true'" in v09,
        "v0.9 must retain full release qualification and selective PR regression",
    )

    proof = read(".github/workflows/trusted-release-proof.yml")
    proof_jobs = section(proof, "jobs") or ""
    build = section(proof_jobs, "build", 2)
    promotion = section(proof_jobs, "dispatch-promotion", 2)
    for job, workflow in RELEASE_INHERITED.items():
        job_body = section(proof_jobs, job, 2)
        require(
            job_body is not None
            and re.search(
                r"(?m)^    uses: " + re.escape("./" + workflow) + r"\s*$",
                job_body or "",
            )
            is not None
            and re.search(r"(?m)^    needs: validate\s*$", job_body or "") is not None
            and re.search(r"(?m)^    (if|continue-on-error):", job_body or "") is None,
            "release proof missing unconditional inherited qualification: " + job,
        )
        for stage, stage_body in (("build", build), ("dispatch-promotion", promotion)):
            needs = re.search(r"(?m)^    needs: \[([^\n]+)\]\s*$", stage_body or "")
            dependencies = (
                set(part.strip() for part in needs.group(1).split(","))
                if needs
                else set()
            )
            require(
                job in dependencies,
                "release proof " + stage + " missing inherited dependency: " + job,
            )
        require(
            promotion is not None
            and ("needs." + job + ".result == 'success'") in promotion,
            "release promotion missing inherited success guard: " + job,
        )

    # Preserve the reviewed conjunction: finding each predicate elsewhere
    # in the YAML does not prohibit an OR or always() bypass.
    # Promotion-condition edits must undergo a deliberate contract review.
    required_successes = ("validate", *RELEASE_INHERITED, "build", "aggregate-proof")
    expected_guard = (
        "$"
        + "{{ "
        + " && ".join(
            "needs." + job + ".result == 'success'" for job in required_successes
        )
        + " }}"
    )
    actual_guards = re.findall(r"(?m)^    if: (.+?)\s*$", promotion or "")
    require(
        actual_guards == [expected_guard],
        "release promotion success guard must be a reviewed conjunction",
    )

    v010 = read(SPECIALIZED["v010"][0])
    vm = read(SPECIALIZED["vm"][0])
    vm_body = section(section(vm, "jobs") or "", "vm", 2) or ""
    build_step = workflow_step(
        vm_body, 4, "name", "Build exact-source acceptance clients"
    )
    build_lines = executable_run_block(build_step, 4)
    require(
        step_is_unconditional(build_step, 4)
        and build_lines[:2]
        == (
            "set -euo pipefail",
            'cargo build --release --locked -p linurad -p linuractl -p linura-firstboot --target-dir "$LINURA_CARGO_TARGET"',
        )
        and build_lines[2:]
        == (
            'if [[ "$ACCEPTANCE_SCENARIO" == firstboot-offline ]]; then',
            '  cargo test --locked -p linura-authorityd --bin linura-authorityd --target-dir "$LINURA_CARGO_TARGET"',
            '  cargo build --release --locked -p linura-authorityd --bin linura-authorityd --target-dir "$LINURA_CARGO_TARGET"',
            "fi",
        ),
        "v0.9: production authority build and unit checks missing from full VM lane",
    )
    install_step = workflow_step(
        vm_body, 4, "name", "Wait for cloud-init and install exact-source binaries"
    )
    install_lines = executable_run_block(install_step, 4)
    install_text = "\\n".join(install_lines)
    require(
        step_is_unconditional(install_step, 4)
        and 'if [[ "$ACCEPTANCE_SCENARIO" == firstboot-offline ]]; then'
        in install_lines
        and '  scp "${ssh_common[@]}" -P 2222 "$LINURA_CARGO_TARGET/release/linura-authorityd" linura@127.0.0.1:/tmp/'
        in install_lines
        and "'sudo -n install -o root -g root -m 0755 /tmp/linura-authorityd /usr/local/bin/linura-authorityd && rm -f /tmp/linura-authorityd'"
        in install_text
        and "  binaries+=(linura-authorityd)" in install_lines
        and 'for name in "${binaries[@]}"; do' in install_lines
        and '  test "$host_sha" = "$guest_sha"' in install_lines
        and '  test "$host_size" = "$guest_size"' in install_lines,
        "v0.9: production authority guest installation or exact-byte identity missing",
    )
    evidence_step = workflow_step(
        vm_body, 4, "name", "Record exact-source VM acceptance evidence"
    )
    evidence_lines = executable_run_block(evidence_step, 4)
    require(
        step_is_unconditional(evidence_step, 4)
        and '    required_binaries.add("linura-authorityd")' in evidence_lines
        and "if set(binaries) != required_binaries:" in evidence_lines
        and '    raise SystemExit("guest executable identity evidence is incomplete or unexpected")'
        in evidence_lines,
        "v0.9: production authority identity must be bound into VM evidence",
    )
    scenario = read("tests/acceptance/002-firstboot-offline.json")
    try:
        steps = json.loads(scenario)
        smoke = [
            entry["command"]
            for entry in steps["steps"]
            if entry.get("name")
            == "verify-production-authority-fails-closed-on-invalid-state-dir"
        ]
        require(
            "linura-authorityd" in steps["requires"]
            and smoke == [V09_AUTHORITY_NEGATIVE_COMMAND],
            "v0.9: production authority negative VM acceptance step missing",
        )
    except (ValueError, TypeError, KeyError) as error:
        require(False, "v0.9: invalid production authority VM scenario: " + str(error))
    require(
        'production = evidence.get("binaries", {}).get("linura-authorityd")' in v09
        and "guest != host" in v09
        and 'raise SystemExit("v0.9 production authority executable identity mismatch")'
        in v09,
        "v0.9: production authority executable evidence not bound to full proof",
    )
    shell_call = section(section(v010, "jobs") or "", "shell-runtime", 2) or ""
    require(
        "    uses: ./.github/workflows/v010-shell-runtime-qualification.yml"
        in shell_call
        and "      source_sha: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}"
        in (section(shell_call, "with", 4) or "") + shell_call,
        "v0.10 must invoke shell runtime with the exact triggering source",
    )
    for workflow, content, job_name, assert_name in (
        ("v0.10", v010, "contract", "Assert exact source"),
        ("VM", vm, "vm", "Assert exact source and load toolchain contract"),
    ):
        jobs = section(content, "jobs") or ""
        body = section(jobs, job_name, 2)
        env = section(content, "env") or ""
        step = workflow_step(body or "", 4, "name", assert_name)
        commands = executable_run_block(step, 4)
        require(
            body is not None
            and env.count(
                "  SOURCE_SHA: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}\n"
            )
            == 1
            and re.search(r"(?m)^[ \t]*defaults\s*:", content) is None
            and specialized_exact_source_checkout(body or "", 4)
            and step_is_unconditional(step, 4)
            and commands[:3]
            == (
                "set -euo pipefail",
                '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
                'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
            ),
            workflow + ": missing exact-source executable binding",
        )

    # The reusable workflow has its own two checkouts. A correctly bound
    # caller cannot compensate for an overridden checkout in either callee job.
    reusable = read(".github/workflows/v010-shell-runtime-qualification.yml")
    reusable_jobs = section(reusable, "jobs") or ""
    reusable_env = section(reusable, "env") or ""
    require(
        reusable_env.count("  SOURCE_SHA: ${{ inputs.source_sha || github.sha }}\n")
        == 1
        and len(re.findall(r"(?m)^\s+SOURCE_SHA:", reusable)) == 1
        and re.search(r"(?m)^[ \t]*defaults\s*:", reusable) is None,
        "v0.10 shell-runtime: exact-source environment must not be overridden",
    )
    for job_name, assertion in (
        ("substrate", "Assert exact source and substrate contract"),
        ("runtime", "Assert exact source and runtime contract"),
    ):
        body = section(reusable_jobs, job_name, 2)
        step = workflow_step(body or "", 4, "name", assertion)
        commands = executable_run_block(step, 4)
        require(
            protected_step_guards(
                body or "", 4, REVIEWED_STEP_CONDITIONS[("v010-reusable", job_name)]
            ),
            "v0.10 shell-runtime "
            + job_name
            + ": required qualification step guard may bypass execution",
        )
        require(
            body is not None
            and re.search(r"(?m)^    (?:if|continue-on-error|defaults):", body or "")
            is None
            and specialized_exact_source_checkout(
                body or "", 4, "ref: ${{ inputs.source_sha || github.sha }}"
            )
            and step_is_unconditional(step, 4)
            and commands[:3]
            == (
                "set -euo pipefail",
                '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
                'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
            ),
            "v0.10 shell-runtime "
            + job_name
            + ": missing exact-source executable binding",
        )
    for filename, job, environment in (
        ("vm-acceptance.yml", "vm", "generic-vm"),
        ("v04-durability-vm.yml", "durability", "generic-vm"),
        ("v04-enospc-recovery-vm.yml", "enospc", "generic-vm"),
        ("v05-executor-verifier-vm.yml", "qualification", "generic-vm"),
        ("v06-managed-lifecycle-vm.yml", "qualification", "generic-vm"),
        ("v09-adversarial-security.yml", "exact-guest", "generic-vm"),
        ("v010-shell-runtime-qualification.yml", "substrate", "arch-hyprland-runtime"),
        ("v010-shell-runtime-qualification.yml", "runtime", "arch-hyprland-runtime"),
    ):
        text = read(".github/workflows/" + filename)
        body = section(text, job, 2) or ""
        step = workflow_step(body, 4, "name", "Prepare guarded qualification storage")
        expected = (
            "      - name: Prepare guarded qualification storage\n"
            "        env:\n"
            "          LINURA_STORAGE_ROOT: ${{ vars.LINURA_STORAGE_ROOT }}\n"
            "          LINURA_STORAGE_ID: ${{ vars.LINURA_STORAGE_ID }}\n"
            "        run: bash scripts/prepare_qualification_storage.sh " + environment
        )
        require(
            step_is_unconditional(step, 4)
            and (step or "").strip() == expected.strip()
            and 0
            <= body.find("id: toolchain_data")
            < body.find("Prepare guarded qualification storage"),
            filename
            + ": missing unconditional reviewed storage preparation for "
            + job,
        )
        require(
            "$RUNNER_TEMP/" not in body
            and "${ARTIFACT_DIR:-" not in body
            and "path: ${{ env.ARTIFACT_DIR }}/" not in body,
            filename + ": root-backed or empty-root artifact fallback is forbidden",
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = check(args.root)
    if args.json:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "ready": not errors,
                    "qualification_evidence": False,
                    "mandatory_jobs": sorted(MANDATORY),
                    "specialized_critical_paths": {
                        k: list(v[1]) for k, v in SPECIALIZED.items()
                    },
                    "errors": errors,
                },
                indent=2,
            )
        )
    else:
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        if not errors:
            print("CI gate routing validated; no qualification is asserted")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
