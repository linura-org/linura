#!/usr/bin/env python3
"""Check mandatory native CI gates and critical specialized qualification routing."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
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
    "codex": (".github/workflows/codex-environment.yml", (
        "AGENTS.md", "docs/codex-development.md",
        "scripts/setup_codex_environment.sh", "scripts/preflight_codex_environment.sh",
        "scripts/maintain_codex_environment.sh", "scripts/run_codex.sh",
        "scripts/lib/codex_source_state.sh", "scripts/lib/bootstrap_rustup.sh",
        "tools/codex/doctor.py", "tools/codex/versions.env",
        "bindings/python/build-requirements.lock", "rust-toolchain.toml",
        "Cargo.lock", "Cargo.toml", "tools/check_validation_gates.py",
        "tests/tooling/test_validation_gates.py")),
    "vm": (".github/workflows/vm-acceptance.yml", (
        "tools/vm.py", "tools/qualification_guest_identity.py",
        "tests/acceptance/008-control1-plan-preview.json",
        "crates/linura-linux-observation/Cargo.toml")),
    "v04-durability": (".github/workflows/v04-durability-vm.yml", (
        "crates/linura-transaction/Cargo.toml",
        "crates/linura-persistence-sqlite/Cargo.toml", "tools/vm.py",
        "tools/qualification_guest_identity.py")),
    "v04-enospc": (".github/workflows/v04-enospc-recovery-vm.yml", (
        "crates/linura-transaction/Cargo.toml",
        "crates/linura-persistence-sqlite/Cargo.toml", "tools/vm.py",
        "tools/qualification_guest_identity.py")),
    "v05": (".github/workflows/v05-executor-verifier-vm.yml", (
        "executors/linura-executor-systemd/Cargo.toml",
        "verifiers/linura-verifier-systemd/Cargo.toml",
        "crates/linura-linux-observation/Cargo.toml",
        "tools/qualification_guest_identity.py")),
    "v06": (".github/workflows/v06-managed-lifecycle-vm.yml", (
        "crates/linura-lifecycle/Cargo.toml",
        "crates/linura-transaction/Cargo.toml",
        "executors/linura-executor-systemd/Cargo.toml",
        "tools/qualification_guest_identity.py")),
    "v07": (".github/workflows/v07-library-qualification.yml", (
        "crates/linura-library/Cargo.toml",
        "crates/linura-intent/Cargo.toml", "scripts/check_repository.py")),
    "v08": (".github/workflows/v08-agent-qualification.yml", (
        "crates/linura-agent-runtime/Cargo.toml",
        "crates/linura-control/Cargo.toml", "scripts/check_repository.py")),
    "v09": (".github/workflows/v09-qualification.yml", (
        "tools/v09_qualification_scope.py",
        "tests/tooling/test_v09_qualification_scope.py",
        "tests/acceptance/002-firstboot-offline.json",
        "contracts/v09-qualification-routing.toml",
        "tools/image.py", "contracts/operation-semantics.toml",
        "tools/check_validation_gates.py", "tests/tooling/test_validation_gates.py",
        "crates/linura-control/Cargo.toml")),
    "v010": (".github/workflows/v010-qualification.yml", (
        "apps/linura-shell/bridge/CMakeLists.txt",
        "contracts/v010-workstation-slices.toml",
        "qualification/v010/shell-runtime/run-shell-runtime.sh",
        "qualification/v010/shell-runtime/native-keyboard.c",
        "tools/verify_tray_keyboard.py",
        "tests/tooling/test_native_keyboard.py",
        ".github/workflows/v010-shell-runtime-qualification.yml",
        "tools/qualification_guest_identity.py")),
    "evidence-publication": (".github/workflows/evidence-publication-checks.yml", (
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
        "docs/adr/README.md")),
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
XTASK_CHECK_BODY = "    run(\"cargo\", &[\"fmt\", \"--all\", \"--check\"])?;\n    run(\n        \"cargo\",\n        &[\n            \"clippy\",\n            \"--workspace\",\n            \"--all-targets\",\n            \"--all-features\",\n            \"--locked\",\n            \"--\",\n            \"-D\",\n            \"warnings\",\n        ],\n    )?;\n    run(\n        \"cargo\",\n        &[\"test\", \"--workspace\", \"--all-features\", \"--locked\"],\n    )?;\n    run(\"python3\", &[\"scripts/check_repository.py\"])?;\n    component_maturity()?;\n    authority_foundation()?;\n    run(\"python3\", &[\"scripts/validate_assets.py\"])?;\n    desktop_identity()?;\n    release_contracts()?;\n    run(\n        \"python3\",\n        &[\n            \"-m\",\n            \"unittest\",\n            \"discover\",\n            \"-s\",\n            \"tests/tooling\",\n            \"-p\",\n            \"test_*.py\",\n        ],\n    )?;\n    Ok(())\n"

PYPI_VERIFICATION_COMMANDS = (
    "set -euo pipefail",
    "PYTHONPATH=bindings/python/src python3 -m unittest discover \\",
    "-s bindings/python/tests -p 'test_*.py'",
    "dist_dir=\"$RUNNER_TEMP/linura-python-dist\"",
    "install_dir=\"$RUNNER_TEMP/linura-python-install\"",
    "rm -rf \"$dist_dir\" \"$install_dir\"",
    "mkdir -p \"$dist_dir\" \"$install_dir\"",
    "python3 -m pip wheel \\",
    "--disable-pip-version-check \\",
    "--no-deps \\",
    "--wheel-dir \"$dist_dir\" \\",
    "./bindings/python",
    "python3 -m pip install \\",
    "--disable-pip-version-check \\",
    "--no-deps \\",
    "--target \"$install_dir\" \\",
    "\"$dist_dir\"/linura-*.whl",
    "PYTHONPATH=\"$install_dir\" python3 - <<'PY'",
    "import linura",
    "assert linura.__version__ == \"0.0.1\"",
    "assert linura.CONTROL1_SERVICE == \"org.linura.Control1\"",
    "assert linura.find_installation(path=\"\") is None",
    "PY",
)


WORKFLOW_CONTROL_KEYS = frozenset((
    "if", "needs", "continue-on-error", "defaults", "on", "pull_request",
    "push", "branches", "branches-ignore", "types", "paths", "paths-ignore",
    "schedule", "cron", "shell", "uses", "with",
))


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
                        decoded = (json.loads(token) if token[0] == '"'
                                   else token[1:-1].replace("''", "'"))
                    except (ValueError, UnicodeError) as exc:
                        raise ValueError("unsupported action reference escape") from exc
                    if re.fullmatch(r"[A-Za-z0-9_./@:-]+", decoded) is None:
                        raise ValueError("noncanonical decoded action reference")
                    line = (line[:action_scalar.start(2)] + decoded +
                            (scalar.group(2) or "") +
                            ("\r\n" if line.endswith("\r\n") else
                             "\n" if line.endswith("\n") else ""))
        if re.search(r":[ \t]*[|>][-+]?[0-9]?[ \t]*(?:#.*)?$", line.rstrip("\r\n")):
            scalar_indent = indent
            result.append(line)
            continue
        if re.match(r"^[ \t]*(?:\?[ \t]+|<<[ \t]*:|\{|(?:-[ \t]+)?[&*!])", line):
            raise ValueError(
                "explicit, merged, anchored, tagged or standalone flow mapping is not audited")
        quoted = re.match(r"""^([ \t]*(?:-[ \t]+)?)(["'])(.*?)\2[ \t]*:""", line)
        if quoted:
            quote, raw = quoted.group(2), quoted.group(3)
            try:
                decoded = (json.loads('"' + raw + '"') if quote == '"'
                           else raw.replace("''", "'"))
            except (ValueError, UnicodeError) as exc:
                raise ValueError("unsupported quoted mapping key encoding") from exc
            if decoded not in WORKFLOW_CONTROL_KEYS:
                raise ValueError("noncanonical quoted mapping key")
            line = quoted.group(1) + decoded + ":" + line[quoted.end():]
        elif re.match(r"^[ \t]*(?:-[ \t]+)?[\"']", line):
            # A quoted sequence value on one line (e.g. a path glob) is safe.
            # Unterminated quoted mapping keys can span lines and evade audit.
            if not re.fullmatch(
                    r"[ \t]*-[ \t]+([\"'])(?:.*)\1[ \t]*(?:#.*)?\r?\n?", line):
                raise ValueError("noncanonical or multiline quoted mapping key")
        else:
            # YAML permits spaces before a plain mapping key's colon. The
            # inspected job/step and checkout guards require canonical keys.
            # Normalize only audited keys, never values or literal run blocks.
            control = "|".join(re.escape(key) for key in sorted(
                WORKFLOW_CONTROL_KEYS, key=len, reverse=True))
            line = re.sub(
                r"^([ \t]*(?:-[ \t]+)?)(" + control + r")[ \t]+:",
                r"\1\2:", line, count=1,
            )
        result.append(line)
    return "".join(result)


def section(text: str, heading: str, indent: int = 0) -> str | None:
    lines = text.splitlines(keepends=True)
    prefix = " " * indent
    for pos, line in enumerate(lines):
        if line.strip() != heading + ":" or not line.startswith(prefix) or line.startswith(prefix + " "):
            continue
        contents = []
        for next_line in lines[pos + 1:]:
            if next_line.strip() and len(next_line) - len(next_line.lstrip(" ")) <= indent:
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
    entries = list(re.finditer(
        r"(?m)^ {" + str(list_indent) + r"}- (?:name|uses|run):[^\n]*$", steps
    ))
    for index, entry in enumerate(entries):
        first = entry.group(0).strip()[2:]
        if first.startswith(key + ": ") and first[len(key) + 2:].startswith(value):
            end = entries[index + 1].start() if index + 1 < len(entries) else len(steps)
            return steps[entry.start():end]
    return None


def step_is_unconditional(
        step: str | None, job_indent: int, *, allow_reviewed_shell: bool = False,
) -> bool:
    """A mandatory step must not be skipped or turn a failure into success.

    The sole explicit-shell exception is for the publisher's first executable
    step. Its precise trusted shell is independently pinned by byte-for-byte
    comparison to reviewed_tests. Every other caller still rejects shell.
    """
    if step is None:
        return False
    prop_indent = job_indent + 4
    guards = "if|continue-on-error" if allow_reviewed_shell else "if|continue-on-error|shell"
    return re.search(
        r"(?m)^ {" + str(prop_indent) + r"}(?:" + guards + r"):", step
    ) is None


def protected_step_guards(
        job_body: str, job_indent: int, reviewed: dict[str, str],
) -> bool:
    """Reject step guards not expressly reviewed for the qualification lane.

    The line-oriented step reader handles canonical block-style entries only;
    run: | source is never interpreted as a workflow mapping.
    """
    steps = section(job_body, "steps", job_indent)
    if steps is None:
        return True  # A reusable-workflow caller has no local executable steps.
    list_indent = job_indent + 2
    headers = list(re.finditer(
        r"(?m)^ {" + str(list_indent) + r"}-[ \t]+[^\r\n]+$", steps,
    ))
    entries = list(re.finditer(
        r"(?m)^ {" + str(list_indent) + r"}- (?:name|uses|run):[^\r\n]*$", steps,
    ))
    if not headers or len(headers) != len(entries):
        return False
    for pos, entry in enumerate(entries):
        end = entries[pos + 1].start() if pos + 1 < len(entries) else len(steps)
        step = steps[entry.start():end]
        heading = entry.group(0).strip()[2:]
        label = heading[len("name:"):].strip() if heading.startswith("name:") else ""
        prop_indent = job_indent + 4
        conditions = re.findall(
            r"(?m)^ {" + str(prop_indent) + r"}if:[ \t]*([^\r\n]*)$", step,
        )
        if (len(conditions) > 1 or
                re.search(r"(?m)^ {" + str(prop_indent) +
                          r"}continue-on-error:", step) is not None):
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
            r"(?m)^ {" + str(job_indent + 2) + r"}-[ \t]*\{", steps):
        return False
    checkout = workflow_step(job_body, job_indent, "uses", "actions/checkout@")
    # GitHub accepts quoted action identifiers and named steps whose "uses"
    # property is on a subsequent line. All of them count as checkouts:
    # a later checkout can silently replace the triggering source.
    occurrences = re.findall(
        r"""(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?actions/checkout@""",
        job_body,
    )
    if (len(occurrences) != 1 or
            not step_is_unconditional(checkout, job_indent) or
            re.search(r"(?m)^ {" + str(job_indent + 2) +
                      r"}- uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
                      checkout or "") is None):
        return False
    # Inline YAML mappings also count as with options; only the audited
    # fetch-depth: 0 option is permitted, never ref, repository, etc.
    with_lines = re.findall(
        r"(?m)^ {" + str(job_indent + 4) + r"}with:(.*)$", checkout or ""
    )
    if not with_lines:
        return True
    options = section(checkout or "", "with", job_indent + 4)
    return (len(with_lines) == 1 and not with_lines[0].strip() and
            options is not None and
            re.fullmatch(r"\s*fetch-depth: 0\s*", options) is not None)


def specialized_exact_source_checkout(
        job_body: str, job_indent: int,
        expected_ref: str = "ref: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}",
) -> bool:
    """Require one unconditional audited checkout bound to SOURCE_SHA."""
    steps = section(job_body, "steps", job_indent)
    if steps is None or re.search(
            r"(?m)^ {" + str(job_indent + 2) + r"}-[ \t]*\{", steps):
        return False
    checkout = workflow_step(job_body, job_indent, "uses", "actions/checkout@")
    occurrences = re.findall(
        r"""(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*['"]?actions/checkout@""",
        job_body,
    )
    if len(occurrences) != 1 or not step_is_unconditional(checkout, job_indent):
        return False
    action = r"(?m)^ {" + str(job_indent + 2) + r"}- uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$"
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
    code = [line for line in lines[lines.index(marker) + 1:] if line.strip()]
    if any(not line.startswith(prefix) for line in code):
        return ()
    return tuple(line[len(prefix):] for line in code)


def path_matches(path: str, pattern: str) -> bool:
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
    return re.fullmatch("".join(tokens), path) is not None


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
        "Stop disposable guest": "always()",
        "Collect VM diagnostics": "always()",
        "Upload unqualified VM diagnostics": "failure()",
    },
    ("v04-durability", "durability"): {
        "Stop disposable guest": "always()",
        "Upload unqualified v0.4 durability diagnostics": "failure()",
    },
    ("v04-enospc", "enospc"): {
        "Record exact-source ENOSPC evidence": "always()",
        "Stop disposable guest": "always()",
        "Upload unqualified ENOSPC diagnostics": "failure()",
    },
    ("v05", "qualification"): {
        "Collect executor hardening evidence": "always()",
        "Stop disposable guest": "always()",
        "Collect QEMU diagnostics": "always()",
        "Upload unqualified v05-executor-verifier diagnostics": "failure()",
    },
    ("v06", "qualification"): {
        "Collect authority and executor hardening evidence": "always()",
        "Stop disposable guest": "always()",
        "Collect QEMU diagnostics": "always()",
        "Upload unqualified v06-managed-lifecycle diagnostics": "failure()",
    },
    ("v07", "qualification"): {
        "Upload unqualified v0.7 diagnostics": "failure()",
    },
    ("v08", "qualification"): {
        "Upload unqualified v0.8 diagnostics": "failure()",
    },
    ("v09", "contract"): {
        "Build exact-source adversarial qualification binaries":
            "needs.scope.outputs.full_qualification == 'true'",
        "Upload exact-source adversarial qualification binaries":
            "needs.scope.outputs.full_qualification == 'true'",
    },
    ("v010-reusable", "substrate"): {
        "Install disposable substrate builder dependencies":
            "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Restore official Arch base-image cache":
            "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Download and verify official Arch base image":
            "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Build sanitized prepared runtime substrate":
            "steps.prepared-substrate.outputs.cache-hit != 'true'",
        "Save prepared runtime substrate":
            "steps.prepared-substrate.outputs.cache-hit != 'true'",
    },
    ("v010-reusable", "runtime"): {
        "Stop disposable guest": "always()",
        "Collect QEMU diagnostics": "always()",
        "Upload unqualified v0.10 shell diagnostics": "failure()",
    },
}


GUIDANCE_EXCLUSIONS = {
    "v010": ("apps/linura-shell/AGENTS.md", "apps/linura-shell/README.md"),
}


CODEX_REQUIRED_STEPS = (
    ("Prepare isolated environment",
     ('task_home="$RUNNER_TEMP/linura-codex-home"', '"$GITHUB_ENV"')),
    ("Bootstrap from host primitives",
     ("run: PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings",)),
    ("Inject stale bindings distribution before maintenance",
     ("linura-contaminant-0.0.1.dist-info",
      "if python3 tools/codex/doctor.py --profile bindings --json",
      "exit 1")),
    ("Resume cached environment at selected checkout",
     ("run: PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings",)),
    ("Verify maintenance removed contaminated distributions",
     ("python3 tools/codex/doctor.py --profile bindings --json",
      '"linura-contaminant"')),
    ("Verify from a separate task process",
     ("scripts/preflight_codex_environment.sh --full",
      "--no-index --no-deps --no-build-isolation")),
)


CODEX_CONTAMINATION_COMMANDS = (
    "set -euo pipefail",
    "\"$HOME/.local/linura-tools/python/bin/python3\" - <<'PY'",
    "import pathlib",
    "import sysconfig",
    "site = pathlib.Path(sysconfig.get_paths()[\"purelib\"])",
    "stale = site / \"linura-contaminant-0.0.1.dist-info\"",
    "stale.mkdir()",
    "(stale / \"METADATA\").write_text(",
    "    \"Metadata-Version: 2.1\\nName: linura-contaminant\\nVersion: 0.0.1\\n\"",
    ")",
    "PY",
    "if python3 tools/codex/doctor.py --profile bindings --json > \"$RUNNER_TEMP/contaminated-bindings.json\"; then",
    "  echo \"doctor accepted an undeclared cached distribution\" >&2",
    "  exit 1",
    "fi",
)


# Review the complete executable content, not just tokens that could occur
# after an early exit or in a shell comment. The six required steps are all
# covered: these four plus the injection and task-time verification below.
CODEX_OTHER_EXECUTION_CONTRACTS = {
    "Prepare isolated environment": (
        "set -euo pipefail",
        "task_home=\"$RUNNER_TEMP/linura-codex-home\"",
        "mkdir -p \"$task_home\"",
        "{",
        "  printf 'HOME=%s\\n' \"$task_home\"",
        "  printf 'CARGO_HOME=%s/.cargo\\n' \"$task_home\"",
        "  printf 'RUSTUP_HOME=%s/.rustup\\n' \"$task_home\"",
        "} >> \"$GITHUB_ENV\"",
    ),
    "Bootstrap from host primitives": "PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings",
    "Resume cached environment at selected checkout": "PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings",
    "Verify maintenance removed contaminated distributions": (
        "set -euo pipefail",
        "python3 tools/codex/doctor.py --profile bindings --json > \"$RUNNER_TEMP/clean-bindings.json\"",
        "\"$HOME/.local/linura-tools/python/bin/python3\" - <<'PY'",
        "import importlib.metadata as metadata",
        "assert all(dist.metadata[\"Name\"] != \"linura-contaminant\" for dist in metadata.distributions())",
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
        expected_needs = ([] if controls["needs"] is None else [controls["needs"]])
        if needs != expected_needs:
            return False
        guards = re.findall(r"(?m)^    if:[ \t]*(.+?)[ \t]*$", body)
        expected_guard = ([] if controls["if"] is None else [controls["if"]])
        if guards != expected_guard:
            return False
        uses = re.findall(r"(?m)^    uses:[ \t]*(.+?)[ \t]*$", body)
        expected_uses = ([] if controls["uses"] is None else [controls["uses"]])
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
        line.strip() for line in (outputs or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if output_entries != [
            "full_qualification: ${{ steps.route.outputs.full_qualification }}"]:
        return False
    route = workflow_step(scope, 4, "name", "Resolve exact-source qualification lane")
    if (not step_is_unconditional(route, 4) or
            re.findall(r"(?m)^        id:[ \t]*(\S+)[ \t]*$", route or "") != ["route"] or
            len(re.findall(r"(?m)^        id:[ \t]*route[ \t]*$", scope)) != 1):
        return False
    marker = "        run: |"
    lines = (route or "").splitlines()
    if lines.count(marker) != 1:
        return False
    body = lines[lines.index(marker) + 1:]
    while body and not body[-1].strip():
        body.pop()
    if (not body or
            any(line.strip() and not line.startswith("          ") for line in body)):
        return False
    run = "\n".join(line[10:] if line else "" for line in body) + "\n"
    heredoc = 'python3 - "$changed" "$GITHUB_OUTPUT" <<\'PY\'\n'
    parts = run.split(heredoc)
    if len(parts) != 2 or not parts[1].endswith("PY\n"):
        return False
    shell = parts[0]
    source = parts[1][:-len("PY\n")]
    executable_shell = tuple(
        line.strip() for line in shell.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected_shell = (
        "set -euo pipefail",
        'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
        'if [[ "$GITHUB_EVENT_NAME" != "pull_request" ]]; then',
        'printf \'full_qualification=true\\n\' >> "$GITHUB_OUTPUT"',
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
    expected_source = textwrap.dedent(r'''          import os
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
              print(path)''')
    try:
        return ast.dump(ast.parse(source), include_attributes=False) == ast.dump(
            ast.parse(expected_source), include_attributes=False)
    except SyntaxError:
        return False

def check(root: Path = ROOT) -> list[str]:
    failures = []

    def require(value: bool, reason: str) -> None:
        if not value:
            failures.append(reason)

    def read(name: str) -> str:
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
                    failures.append("unsafe workflow mapping syntax: " + name +
                                    ": " + str(exc))
                    return ""
            return content
        except (OSError, UnicodeError):
            failures.append("unreadable gate input: " + name)
            return ""

    mandatory_bodies: dict[str, tuple[str, int] | None] = {}
    for job, path in MANDATORY.items():
        source = read(path)
        events = section(source, "on")
        require(events is not None, job + ": missing event map")
        pr = section(events or "", "pull_request", 2)
        push = section(events or "", "push", 2)
        # A mandatory native gate must not silently disappear for particular
        # target branches, PR events, or paths. Keep pull_request unqualified:
        # GitHub's default opened/reopened/synchronize events are intentional.
        # A bare pull_request event has no non-comment children at any YAML
        # indentation. Anchoring on four spaces permits valid deeper filters.
        require(pr is not None and
                all(not line.strip() or line.lstrip().startswith("#")
                    for line in pr.splitlines()),
                job + ": must run on every PR without branch, type, or path filters")
        require(push is not None and re.search(r"(?m)^    branches: \[main\]\s*$", push or "") is not None
                and not re.search(r"(?m)^    (paths|paths-ignore|branches-ignore):", push or ""),
                job + ": must run on every main push")
        if job in ("dependency-audit", "analyze"):
            # Independent scheduled scans detect new advisories even when idle.
            expected = ("17 4 * * 1" if job == "dependency-audit" else
                        "41 3 * * 3")
            schedule = section(events or "", "schedule", 2)
            entries = [line.strip() for line in (schedule or "").splitlines()
                       if line.strip()]
            require(entries == [f'- cron: "{expected}"'],
                    job + ": must retain reviewed independent weekly scheduled scan")
        jobs = section(source, "jobs")
        required_job = section(jobs or "", job, 2)
        require(required_job is not None, job + ": native check job removed")
        # Valid YAML may indent direct job properties six (or more) spaces.
        # Anchor all skip/dependency guards at the actual mapping indentation.
        runner = re.search(r"(?m)^( +)runs-on:", required_job or "")
        job_indent = len(runner.group(1)) if runner else 0
        mandatory_bodies[job] = ((required_job, job_indent)
                                  if required_job is not None and job_indent else None)
        require(required_job is not None and job_indent > 2 and
                re.search(r"(?m)^ {" + str(job_indent) +
                          r"}(?:if|needs|continue-on-error):", required_job or "") is None,
                job + ": mandatory job must be unconditional and independent")
        # Required checks must analyze the triggering GitHub revision, not an
        # independently selected branch. A second checkout could replace the
        # source after an initially correct checkout, so allow exactly one.
        require(checkout_is_triggering_revision(required_job or "", job_indent),
                job + ": must checkout triggering revision without a ref override")
        require("continue-on-error:" not in source, job + ": fail-open flag prohibited")
        # Inherited workflow/job shells can exit successfully without running
        # an otherwise exact mandatory command. No run defaults are needed here.
        require(re.search(r"(?m)^[ \t]*defaults\s*:", source) is None,
                job + ": run defaults may bypass mandatory executable steps")

    ci = read(MANDATORY["canonical-check"])
    xtask = read("tools/xtask/src/main.rs")
    canonical = mandatory_bodies.get("canonical-check")
    if canonical:
        body, indent = canonical
        # No job-level container, alternate runner, service, custom strategy,
        # privilege or environment escape hatch may precede the suite.
        # An untrusted container can replace every absolute system binary
        # before pinned checkout/setup-node even begin.
        direct_properties = [
            line for line in body.splitlines()
            if line.strip() and line.startswith(" " * indent)
            and not line.startswith(" " * (indent + 1))
            and not line.lstrip().startswith("#")
        ]
        require(
            direct_properties == [
                " " * indent + "runs-on: ubuntu-24.04",
                " " * indent + "steps:",
            ],
            "canonical CI publisher job must use exact trusted hosted runner"
            " without container or alternate job configuration",
        )
        for label, command in (
            ("Run canonical Linura checks", "cargo xtask check"),
            ("Verify canonical crates.io package", "cargo package --locked -p linura"),
            ("Verify canonical PyPI package",
             "PYTHONPATH=bindings/python/src python3 -m unittest discover"),
        ):
            step = workflow_step(body, indent, "name", label)
            prop_indent = indent + 4
            run = re.search(r"(?m)^ {" + str(prop_indent) +
                            r"}run: (.+)$", step or "")
            actual = run.group(1).strip() if run else ""
            if label == "Verify canonical PyPI package":
                # Protect the whole approved shell block. A substring check
                # accepts early exits, disabled tests and skipped wheel imports.
                marker = " " * prop_indent + "run: |"
                lines = (step or "").splitlines()
                actual_commands = ([line.strip() for line in lines[lines.index(marker) + 1:]
                                    if line.strip()] if marker in lines else [])
                executable = actual == "|" and tuple(actual_commands) == PYPI_VERIFICATION_COMMANDS
            else:
                executable = actual == command
            # A step-level SHELLOPTS/BASH_ENV mapping can render an exact
            # reviewed command a no-op. These three native gate steps have
            # no approved environment override; reject every step-level env.
            injected_env = re.search(
                r"(?m)^ {" + str(prop_indent) + r"}env\s*:", step or ""
            )
            require(step_is_unconditional(step, indent)
                    and injected_env is None and executable,
                    "canonical CI missing unconditional executable step: " + label)
    # There is no reviewed workflow- or job-level environment mapping in
    # canonical CI. Such mappings can inject readonly Bash startup flags
    # (SHELLOPTS=noexec) across otherwise exact native qualification commands.
    # The publisher's protected step also runs this policy checker itself,
    # after clearing shell startup variables, before any Node test invocation.
    require(re.search(r"(?m)^(?:env|    env)\s*:", ci) is None,
            "canonical CI may not inherit workflow/job environment variables")
    # Publisher source is a separate merge authority, so its Node security
    # suite must remain in the unfiltered native CI gate. A path-filtered
    # publisher workflow cannot defend a PR editing only canonical CI.
    if canonical:
        body, indent = canonical
        reviewed_node = (
            "      - name: Install pinned Node runtime for trusted publisher tests\n"
            "        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0\n"
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
            "          /usr/bin/python3 -I -S - <<'PY'\n"
            "          import hashlib\n"
            "          import os\n"
            "          from pathlib import Path\n"
            "          import re\n"
            "          import subprocess\n"
            "          \n"
            "          def deny(message):\n"
            "              raise SystemExit(\"publisher source provenance denied: \" + message)\n"
            "          \n"
            "          sha = os.environ.get(\"GITHUB_SHA\", \"\")\n"
            "          if not re.fullmatch(r\"[0-9a-f]{40}\", sha):\n"
            "              deny(\"invalid triggering SHA\")\n"
            "          git_env = {\"PATH\": \"/usr/bin:/bin\", \"HOME\": \"/nonexistent\",\n"
            "                     \"GIT_CONFIG_NOSYSTEM\": \"1\", \"GIT_CONFIG_GLOBAL\": \"/dev/null\",\n"
            "                     \"GIT_NO_REPLACE_OBJECTS\": \"1\"}\n"
            "          \n"
            "          def git(*args):\n"
            "              result = subprocess.run([\"/usr/bin/git\", *args], env=git_env,\n"
            "                                      check=False, stdout=subprocess.PIPE,\n"
            "                                      stderr=subprocess.DEVNULL, timeout=20)\n"
            "              if result.returncode:\n"
            "                  deny(\"cannot read source commit\")\n"
            "              return result.stdout\n"
            "          \n"
            "          if git(\"rev-parse\", \"--verify\", \"HEAD^{commit}\").strip().decode(\"ascii\") != sha:\n"
            "              deny(\"checkout is not the triggering revision\")\n"
            "          scopes = (\".github/workflows/ci.yml\", \"tools/check_validation_gates.py\",\n"
            "                    \"tests/tooling/test_validation_gates.py\", \"services/qualification-publisher\")\n"
            "          raw_tree = git(\"ls-tree\", \"-r\", \"-z\", \"--full-tree\", sha, \"--\", *scopes)\n"
            "          expected = {}\n"
            "          for item in raw_tree.split(b\"\\x00\"):\n"
            "              if not item:\n"
            "                  continue\n"
            "              try:\n"
            "                  info, path = item.split(b\"\\t\", 1)\n"
            "                  mode, kind, digest = info.split(b\" \")\n"
            "                  name = path.decode(\"utf-8\")\n"
            "              except (ValueError, UnicodeDecodeError):\n"
            "                  deny(\"malformed source tree\")\n"
            "              if (mode not in (b\"100644\", b\"100755\") or kind != b\"blob\"\n"
            "                      or not re.fullmatch(rb\"[0-9a-f]{40}\", digest)\n"
            "                      or name in expected):\n"
            "                  deny(\"unsafe source tree entry\")\n"
            "              expected[name] = digest.decode(\"ascii\")\n"
            "          root = Path.cwd()\n"
            "          seen = set()\n"
            "          def visit(path):\n"
            "              if path.is_symlink():\n"
            "                  deny(\"source symlink\")\n"
            "              if path.is_dir():\n"
            "                  for entry in path.iterdir():\n"
            "                      visit(entry)\n"
            "              elif path.is_file():\n"
            "                  relative = path.relative_to(root).as_posix()\n"
            "                  if relative not in expected:\n"
            "                      deny(\"unexpected source file\")\n"
            "                  data = path.read_bytes()\n"
            "                  actual = hashlib.sha1(b\"blob \" + str(len(data)).encode(\"ascii\")\n"
            "                                        + b\"\\x00\" + data).hexdigest()\n"
            "                  if actual != expected[relative]:\n"
            "                      deny(\"source differs from triggering commit\")\n"
            "                  seen.add(relative)\n"
            "              else:\n"
            "                  deny(\"missing or special source entry\")\n"
            "          for scope in scopes:\n"
            "              path = root / scope\n"
            "              if not path.exists() and not path.is_symlink():\n"
            "                  deny(\"missing protected source\")\n"
            "              visit(path)\n"
            "          if seen != set(expected) or len(seen) < 6:\n"
            "              deny(\"incomplete protected source inventory\")\n"
            "          print(\"publisher tests bound to triggering source SHA\")\n"
            "          PY\n"
            "          /usr/bin/python3 -I -S tools/check_validation_gates.py\n"
            "          test \"$(/usr/bin/env -i PATH=\"$PATH\" LANG=C.UTF-8 node --version)\" = 'v22.23.3'\n"
            "          /usr/bin/env -i PATH=\"$PATH\" LANG=C.UTF-8 node --check services/qualification-publisher/publisher.mjs\n"
            "          /usr/bin/env -i PATH=\"$PATH\" LANG=C.UTF-8 node --check services/qualification-publisher/server.mjs\n"
            "          /usr/bin/env -i PATH=\"$PATH\" LANG=C.UTF-8 node --test services/qualification-publisher/test/*.test.mjs\n"
        )
        for label, expected in (
            ("Install pinned Node runtime for trusted publisher tests", reviewed_node),
            ("Validate trusted qualification publisher in canonical CI", reviewed_tests),
        ):
            step = workflow_step(body, indent, "name", label)
            require(
                step_is_unconditional(
                    step, indent,
                    allow_reviewed_shell=(
                        label == "Validate trusted qualification publisher in canonical CI"
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
            body, indent, "uses",
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
            r"(?m)^ {" + str(step_indent) +
            r"}- (?:name|uses|run):[^\r\n]*$",
            steps_body,
        )
        checkout_header = " " * step_indent + (
            "- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
        )
        setup_header = " " * step_indent + "- name: Install pinned Node runtime for trusted publisher tests"
        test_header = " " * step_indent + "- name: Validate trusted qualification publisher in canonical CI"
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
    actual_body = (pieces[1].split("\n}\n")[0] + "\n"
                   if len(pieces) == 2 and "\n}\n" in pieces[1] else None)
    require(actual_body == XTASK_CHECK_BODY and
            '"check" => check(),' in xtask,
            "canonical xtask execution sequence changed")

    security = read(MANDATORY["dependency-audit"])
    pins = read("tools/codex/versions.env")
    require(re.search(r"(?m)^CARGO_AUDIT_VERSION=\d+\.\d+\.\d+$", pins) is not None,
            "cargo-audit exact version pin removed")
    for token in ('cargo install cargo-audit --locked --version "$CARGO_AUDIT_VERSION"',
                  'test "$actual_version" = "$CARGO_AUDIT_VERSION"',
                  '"$HOME/.cargo/bin/cargo-audit" audit'):
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
        commands = ([line.strip() for line in lines[lines.index(marker) + 1:]
                     if line.strip()] if marker in lines else [])
        require(step_is_unconditional(audit_step, indent) and commands == [
                    "set -euo pipefail",
                    '"$HOME/.cargo/bin/cargo-audit" audit',
                ], "security audit must run unconditionally")
    for forbidden in ("|| true", "continue-on-error:", "--ignore", "--no-fail"):
        require(forbidden not in security, "security audit may be bypassed: " + forbidden)

    codeql = read(MANDATORY["analyze"])
    codeql_gate = mandatory_bodies.get("analyze")
    if codeql_gate:
        body, indent = codeql_gate
        action_revisions = {}
        for action in ("github/codeql-action/init@", "github/codeql-action/analyze@"):
            step = workflow_step(body, indent, "uses", action)
            pinned = re.search(
                r"(?m)^ {" + str(indent + 2) + r"}- uses: " +
                re.escape(action) + r"([0-9a-f]{40})(?:\s+#.*)?$", step or ""
            )
            require(step_is_unconditional(step, indent) and pinned is not None,
                    "CodeQL missing unconditional SHA-pinned action: " + action)
            if pinned is not None:
                action_revisions[action] = pinned.group(1)
            if action.endswith("/init@"):
                settings = section(step or "", "with", indent + 4)
                # Match the entire setting block. A comment, duplicate YAML
                # key or a different effective language must not satisfy Rust.
                require(settings is not None and
                        re.fullmatch(r"\s*languages: rust,javascript-typescript\s*", settings) is not None,
                        "CodeQL initialization must configure exactly Rust and JavaScript")
        require(
            len(action_revisions) == 2
            and len(set(action_revisions.values())) == 1,
            "CodeQL init/analyze actions must share the same immutable revision",
        )
    codex = read(SPECIALIZED["codex"][0])
    # Workflow- and job-level run defaults override the effective shell of
    # every otherwise reviewed command. Ban inherited defaults, including
    # inline YAML mappings, so a successful no-op shell cannot fake evidence.
    require(re.search(r"(?m)^[ \t]*defaults\s*:", codex) is None,
            "codex: inherited run defaults may bypass required steps")
    codex_jobs = section(codex, "jobs") or ""
    codex_job = section(codex_jobs, "fresh-environment", 2)
    # An unconditional job is insufficient: each required step must execute,
    # rather than leaving its command as dead text in the workflow.
    for label, tokens in CODEX_REQUIRED_STEPS:
        step = workflow_step(codex_job or "", 4, "name", label)
        require(step_is_unconditional(step, 4) and
                re.search(r"(?m)^        run: (?:\||[^\n]+)$", step or "") is not None and
                all(token in (step or "") for token in tokens),
                "Codex required step must execute: " + label)
    for label, expected in CODEX_OTHER_EXECUTION_CONTRACTS.items():
        step = workflow_step(codex_job or "", 4, "name", label)
        direct_run = re.search(r"(?m)^        run: (.+)$", step or "")
        run = direct_run.group(1).strip() if direct_run else ""
        executable = (run == "|" and executable_run_block(step, 4) == expected
                      if isinstance(expected, tuple) else run == expected)
        require(step_is_unconditional(step, 4) and executable,
                "Codex required step must match reviewed executable content: " + label)
    require(checkout_is_triggering_revision(codex_job or "", 4),
            "codex: must checkout triggering revision without a ref override")
    injection = workflow_step(codex_job or "", 4, "name",
                              "Inject stale bindings distribution before maintenance")
    require(step_is_unconditional(injection, 4) and
            executable_run_block(injection, 4) == CODEX_CONTAMINATION_COMMANDS,
            "Codex contamination injection must execute the complete reviewed shell block")
    verification = workflow_step(codex_job or "", 4, "name",
                                 "Verify from a separate task process")
    lines = (verification or "").splitlines()
    marker = "        run: |"
    verification_commands = (
        tuple(line.strip() for line in lines[lines.index(marker) + 1:] if line.strip())
        if marker in lines else ()
    )
    require(verification_commands == (
        "set -euo pipefail",
        "PATH=/usr/bin:/bin bash scripts/preflight_codex_environment.sh --full",
        "PATH=/usr/bin:/bin bash scripts/run_codex.sh cargo --version",
        '"$HOME/.local/linura-tools/python/bin/python3" -m pip wheel \\',
        "--disable-pip-version-check --no-index --no-deps --no-build-isolation \\",
        '--wheel-dir "$RUNNER_TEMP/linura-python-wheel" ./bindings/python',
        "PYTHONPATH=bindings/python/src python3 -m unittest discover \\",
        "-s bindings/python/tests -p 'test_*.py'",
    ), "Codex verification must execute the complete reviewed task-time gate")

    for name, (workflow, critical_paths) in SPECIALIZED.items():
        text = read(workflow)
        # A workflow-level shell default can turn an otherwise protected
        # command into a successful no-op. Keep every specialty fail-closed.
        require(re.search(r"(?m)^[ \t]*defaults\s*:", text) is None,
                name + ": inherited run defaults may bypass qualification")
        events = section(text, "on")
        pr = section(events or "", "pull_request", 2)
        require(pr is not None, name + ": specialized PR event removed")
        # Path-scoped qualification must still run for any target branch and
        # every default PR synchronization event. Explicit branch/type filters
        # and paths-ignore can silently defeat even correctly mapped paths.
        pr_keys = re.findall(r"(?m)^    ([A-Za-z_][\w-]*):", pr or "")
        require(pr is not None and pr_keys == ["paths"],
                name + ": specialized PR event may contain only paths")
        filters = section(pr or "", "paths", 4)
        patterns = re.findall(r"(?m)^      - [\"']([^\"']+)[\"']\s*$", filters or "")
        require(bool(patterns) and len(patterns) == len(set(patterns)),
                name + ": missing or duplicated path filters")
        require(all(pattern != "!" for pattern in patterns),
                name + ": empty negative PR filter")
        require(any(not pattern.startswith("!") for pattern in patterns),
                name + ": specialized PR triggers must include a positive path")
        require(path_selected(workflow, patterns),
                name + ": missing critical PR trigger: " + workflow)
        for path in critical_paths:
            require((root / path).is_file(), name + ": missing critical source: " + path)
            require(path_selected(path, patterns),
                    name + ": missing critical PR trigger: " + path)
        if name in ("codex", "evidence-publication"):
            push = section(events or "", "push", 2)
            push_keys = re.findall(r"(?m)^    ([A-Za-z_][\w-]*):", push or "")
            require(push is not None and push_keys == ["branches", "paths"] and
                    re.search(r"(?m)^    branches: \[main\]\s*$", push or "") is not None,
                    name + ": main-push trigger must target main with scoped paths")
            push_paths = section(push or "", "paths", 4)
            push_patterns = re.findall(
                r"(?m)^      - [\"']([^\"']+)[\"']\s*$", push_paths or ""
            )
            require(bool(push_patterns) and len(push_patterns) == len(set(push_patterns)) and
                    path_selected(workflow, push_patterns) and
                    all(path_selected(path, push_patterns) for path in critical_paths),
                    name + ": main-push routing must cover critical sources")
        jobs = section(text, "jobs") or ""
        for required_job in SPECIALIZED_REQUIRED_JOBS[name]:
            job_body = section(jobs, required_job, 2)
            # Derive the actual direct-property indentation instead of assuming
            # a fixed YAML layout. Nested step conditions are not job guards.
            mapping = re.search(r"(?m)^( +)(?:runs-on|uses|needs|name):",
                                job_body or "")
            indent = len(mapping.group(1)) if mapping else 0
            require(job_body is not None and indent > 2 and
                    re.search(r"(?m)^ {" + str(indent) +
                              r"}(?:if|continue-on-error):", job_body or "") is None,
                    name + ": required qualification job cannot be skipped: " + required_job)
            # Only the v0.9 contract depends on another required entry job.
            # Any other needs edge can silently skip qualification if its
            # prerequisite is skipped under GitHub's default success guard.
            approved_needs = (["scope"] if name == "v09" and
                              required_job == "contract" else [])
            declared_needs = re.findall(
                r"(?m)^ {" + str(indent) + r"}needs:\s*(.*?)\s*$",
                job_body or "",
            )
            require(declared_needs == approved_needs,
                    name + ": required qualification job has unapproved dependencies: " +
                    required_job)
            require(protected_step_guards(
                        job_body or "", indent,
                        REVIEWED_STEP_CONDITIONS.get((name, required_job), {})),
                    name + ": required qualification step guard may bypass execution: " +
                    required_job)
            # A protected job may not inherit a replacement run shell either.
            require(re.search(r"(?m)^ {" + str(indent) +
                              r"}defaults\s*:", job_body or "") is None,
                    name + ": inherited run defaults may bypass qualification: " +
                    required_job)
            # Explicit bash is already used by the v0.7/v0.8 lanes. Arbitrary
            # step shells could suppress tests even without inherited defaults.
            declared_shells = re.findall(
                r"(?m)^ {" + str(indent + 4) + r"}shell:[ \t]*([^\r\n]*)$",
                job_body or "",
            )
            require(all(re.fullmatch(r"bash(?:[ \t]+#.*)?", shell.strip())
                        is not None for shell in declared_shells),
                    name + ": unapproved step shell may bypass qualification: " +
                    required_job)

        if name == "evidence-publication":
            # Path routing and job presence are insufficient if the check
            # itself can be turned into a passing no-op. Pin this credential-
            # boundary's source checkout and its exact executable test step.
            verify = section(jobs, "verify", 2) or ""
            checkout = workflow_step(verify, 4, "uses", "actions/checkout@")
            require(checkout is not None and
                    len(re.findall(r"(?m)^[ ]{6}- uses: actions/checkout@", verify)) == 1 and
                    step_is_unconditional(checkout, 4) and
                    re.search(r"(?m)^      - uses: actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$", checkout) is not None and
                    re.findall(r"(?m)^        with:\s*$", checkout) == ["        with:"] and
                    re.findall(r"(?m)^          [^\s].*$", checkout) ==
                    ["          persist-credentials: false"],
                    "evidence-publication: required verified-source checkout missing or weakened")
            step_name = "Test admission, provenance, privacy and R2 publishing behavior"
            verification = workflow_step(verify, 4, "name", step_name)
            command = "python3 -m unittest -v tests.tooling.test_evidence_publication"
            require(verification is not None and
                    len(re.findall(r"(?m)^      - name: " + re.escape(step_name) + "$", verify)) == 1 and
                    step_is_unconditional(verification, 4) and
                    re.findall(r"(?m)^        run: (.*)$", verification) == [command],
                    "evidence-publication: required test execution missing or weakened")

        for path in GUIDANCE_EXCLUSIONS.get(name, ()):
            require(not path_selected(path, patterns),
                    name + ": guidance-only change triggers machine qualification: " + path)

    v09 = read(SPECIALIZED["v09"][0])
    routing_contract = read("contracts/v09-qualification-routing.toml")
    try:
        contract = tomllib.loads(routing_contract)
        require(contract.get("schema_version") == 1 and
                contract.get("guidance_only_basenames") == ["AGENTS.md", "README.md"],
                "v0.9: invalid routing contract")
        events = section(v09, "on") or ""
        pr = section(events, "pull_request", 2) or ""
        filters = section(pr, "paths", 4) or ""
        patterns = re.findall(r'(?m)^      - "([^"]+)"', filters)
        # Pin every reviewed exact input independently from the mutable
        # contract so a route cannot delete itself from both classification
        # and validation in one edit.
        for required in V09_REQUIRED_FULL_EXACT:
            require(required in contract["full_exact"],
                    "v0.9: missing required full-qualification exact input: " + required)
        for guard in V09_ROUTING_GUARD_EXACT:
            require(guard in contract["full_exact"],
                    "v0.9: missing required routing guard full qualification: " + guard)
        for harness in ("tools/acceptance.py", "scripts/qualification/v09-adversarial-guest.sh"):
            require(harness in contract["full_exact"],
                    "v0.9: missing required full-qualification harness: " + harness)
        for required in (".cargo/config", ".cargo/config.toml"):
            require(required in contract["full_exact"],
                    "v0.9: missing required full-qualification toolchain: " + required)
        require("packaging/wireplumber/linura-session-audio.lua" in contract["full_exact"],
                "v0.9: missing embedded audio helper qualification input")
        # The reviewed full-impact prefix set is a security contract, not a
        # self-describing allowlist. A contract edit cannot delete a route and
        # thereby make the validator forget that the route was mandatory.
        for prefix in V09_REQUIRED_FULL_PREFIXES:
            require(prefix in contract["full_prefixes"],
                    "v0.9: missing required full-qualification prefix: " + prefix)
        for path in contract["full_exact"]:
            require(path_selected(path, patterns),
                    "v0.9: untriggered full-qualification path: " + path)
        for prefix in contract["full_prefixes"]:
            require(path_selected(prefix + "__routing-probe__.rs", patterns),
                    "v0.9: untriggered full-qualification prefix: " + prefix)
    except (ValueError, KeyError, TypeError) as error:
        require(False, "v0.9: invalid routing contract: " + str(error))
    require(v09_classifier_connected(v09),
            "v0.9: shared qualification classifier disconnected")
    require(v09_lane_job_graph_connected(v09),
            "v0.9: qualification lane job graph disconnected")
    require('if [[ "$GITHUB_EVENT_NAME" != "pull_request" ]]; then' in v09 and
            "full_qualification=true" in v09 and
            "full_qualification != 'true'" in v09,
            "v0.9 must retain full release qualification and selective PR regression")

    proof = read(".github/workflows/trusted-release-proof.yml")
    proof_jobs = section(proof, "jobs") or ""
    build = section(proof_jobs, "build", 2)
    promotion = section(proof_jobs, "dispatch-promotion", 2)
    for job, workflow in RELEASE_INHERITED.items():
        job_body = section(proof_jobs, job, 2)
        require(job_body is not None and
                re.search(r"(?m)^    uses: " + re.escape("./" + workflow) + r"\s*$",
                          job_body or "") is not None and
                re.search(r"(?m)^    needs: validate\s*$", job_body or "") is not None and
                re.search(r"(?m)^    (if|continue-on-error):", job_body or "") is None,
                "release proof missing unconditional inherited qualification: " + job)
        for stage, stage_body in (("build", build), ("dispatch-promotion", promotion)):
            needs = re.search(r"(?m)^    needs: \[([^\n]+)\]\s*$", stage_body or "")
            dependencies = (set(part.strip() for part in needs.group(1).split(","))
                            if needs else set())
            require(job in dependencies,
                    "release proof " + stage + " missing inherited dependency: " + job)
        require(promotion is not None and
                ("needs." + job + ".result == 'success'") in promotion,
                "release promotion missing inherited success guard: " + job)

    # Preserve the reviewed conjunction: finding each predicate elsewhere
    # in the YAML does not prohibit an OR or always() bypass.
    # Promotion-condition edits must undergo a deliberate contract review.
    required_successes = ("validate", *RELEASE_INHERITED, "build", "aggregate-proof")
    expected_guard = "$" + "{{ " + " && ".join(
        "needs." + job + ".result == 'success'" for job in required_successes
    ) + " }}"
    actual_guards = re.findall(r"(?m)^    if: (.+?)\s*$", promotion or "")
    require(actual_guards == [expected_guard],
            "release promotion success guard must be a reviewed conjunction")

    v010 = read(SPECIALIZED["v010"][0])
    vm = read(SPECIALIZED["vm"][0])
    vm_body = section(section(vm, "jobs") or "", "vm", 2) or ""
    build_step = workflow_step(vm_body, 4, "name", "Build exact-source acceptance clients")
    build_lines = executable_run_block(build_step, 4)
    require(step_is_unconditional(build_step, 4) and
            build_lines[:2] == (
                "set -euo pipefail",
                "cargo build --release --locked -p linurad -p linuractl -p linura-firstboot",
            ) and
            build_lines[2:] == (
                'if [[ "$ACCEPTANCE_SCENARIO" == firstboot-offline ]]; then',
                "  cargo test --locked -p linura-authorityd --bin linura-authorityd",
                "  cargo build --release --locked -p linura-authorityd --bin linura-authorityd",
                "fi",
            ),
            "v0.9: production authority build and unit checks missing from full VM lane")
    install_step = workflow_step(
        vm_body, 4, "name", "Wait for cloud-init and install exact-source binaries")
    install_lines = executable_run_block(install_step, 4)
    install_text = "\\n".join(install_lines)
    require(step_is_unconditional(install_step, 4) and
            'if [[ "$ACCEPTANCE_SCENARIO" == firstboot-offline ]]; then' in install_lines and
            '  scp "${ssh_common[@]}" -P 2222 target/release/linura-authorityd linura@127.0.0.1:/tmp/' in install_lines and
            "'sudo -n install -o root -g root -m 0755 /tmp/linura-authorityd /usr/local/bin/linura-authorityd && rm -f /tmp/linura-authorityd'" in install_text and
            '  binaries+=(linura-authorityd)' in install_lines and
            'for name in "${binaries[@]}"; do' in install_lines and
            '  test "$host_sha" = "$guest_sha"' in install_lines and
            '  test "$host_size" = "$guest_size"' in install_lines,
            "v0.9: production authority guest installation or exact-byte identity missing")
    evidence_step = workflow_step(
        vm_body, 4, "name", "Record exact-source VM acceptance evidence")
    evidence_lines = executable_run_block(evidence_step, 4)
    require(step_is_unconditional(evidence_step, 4) and
            '    required_binaries.add("linura-authorityd")' in evidence_lines and
            'if set(binaries) != required_binaries:' in evidence_lines and
            '    raise SystemExit("guest executable identity evidence is incomplete or unexpected")'
            in evidence_lines,
            "v0.9: production authority identity must be bound into VM evidence")
    scenario = read("tests/acceptance/002-firstboot-offline.json")
    try:
        steps = json.loads(scenario)
        smoke = [entry["command"] for entry in steps["steps"]
                 if entry.get("name") ==
                 "verify-production-authority-fails-closed-on-invalid-state-dir"]
        require("linura-authorityd" in steps["requires"] and
                smoke == [V09_AUTHORITY_NEGATIVE_COMMAND],
                "v0.9: production authority negative VM acceptance step missing")
    except (ValueError, TypeError, KeyError) as error:
        require(False, "v0.9: invalid production authority VM scenario: " + str(error))
    require('production = evidence.get("binaries", {}).get("linura-authorityd")' in v09 and
            'guest != host' in v09 and
            'raise SystemExit("v0.9 production authority executable identity mismatch")' in v09,
            "v0.9: production authority executable evidence not bound to full proof")
    shell_call = section(section(v010, "jobs") or "", "shell-runtime", 2) or ""
    require("    uses: ./.github/workflows/v010-shell-runtime-qualification.yml" in shell_call and
            "      source_sha: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}" in
            (section(shell_call, "with", 4) or "") + shell_call,
            "v0.10 must invoke shell runtime with the exact triggering source")
    for workflow, content, job_name, assert_name in (
            ("v0.10", v010, "contract", "Assert exact source"),
            ("VM", vm, "vm", "Assert exact source and load toolchain contract")):
        jobs = section(content, "jobs") or ""
        body = section(jobs, job_name, 2)
        env = section(content, "env") or ""
        step = workflow_step(body or "", 4, "name", assert_name)
        commands = executable_run_block(step, 4)
        require(body is not None and
                env.count("  SOURCE_SHA: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}\n") == 1 and
                re.search(r"(?m)^[ \t]*defaults\s*:", content) is None and
                specialized_exact_source_checkout(body or "", 4) and
                step_is_unconditional(step, 4) and
                commands[:3] == (
                    "set -euo pipefail",
                    '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
                    'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
                ), workflow + ": missing exact-source executable binding")

    # The reusable workflow has its own two checkouts. A correctly bound
    # caller cannot compensate for an overridden checkout in either callee job.
    reusable = read(".github/workflows/v010-shell-runtime-qualification.yml")
    reusable_jobs = section(reusable, "jobs") or ""
    reusable_env = section(reusable, "env") or ""
    require(reusable_env.count("  SOURCE_SHA: ${{ inputs.source_sha || github.sha }}\n") == 1 and
            len(re.findall(r"(?m)^\s+SOURCE_SHA:", reusable)) == 1 and
            re.search(r"(?m)^[ \t]*defaults\s*:", reusable) is None,
            "v0.10 shell-runtime: exact-source environment must not be overridden")
    for job_name, assertion in (
            ("substrate", "Assert exact source and substrate contract"),
            ("runtime", "Assert exact source and runtime contract")):
        body = section(reusable_jobs, job_name, 2)
        step = workflow_step(body or "", 4, "name", assertion)
        commands = executable_run_block(step, 4)
        require(protected_step_guards(
                    body or "", 4,
                    REVIEWED_STEP_CONDITIONS[("v010-reusable", job_name)]),
                "v0.10 shell-runtime " + job_name +
                ": required qualification step guard may bypass execution")
        require(body is not None and
                re.search(r"(?m)^    (?:if|continue-on-error|defaults):", body or "") is None and
                specialized_exact_source_checkout(
                    body or "", 4, "ref: ${{ inputs.source_sha || github.sha }}") and
                step_is_unconditional(step, 4) and
                commands[:3] == (
                    "set -euo pipefail",
                    '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
                    'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
                ), "v0.10 shell-runtime " + job_name +
                ": missing exact-source executable binding")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = check(args.root)
    if args.json:
        print(json.dumps({"schema_version": 1, "ready": not errors,
                          "qualification_evidence": False, "mandatory_jobs": sorted(MANDATORY),
                          "specialized_critical_paths": {k: list(v[1]) for k, v in SPECIALIZED.items()},
                          "errors": errors}, indent=2))
    else:
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        if not errors:
            print("CI gate routing validated; no qualification is asserted")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
