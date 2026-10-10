#!/usr/bin/env python3
"""Resolve and enforce the reviewed PR qualification-gate matrix."""

from __future__ import annotations

import argparse
import ast
import base64
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import tomllib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("contracts/qualification-gate-matrix.toml")
ENVELOPE_CONTRACT_PATH = Path("contracts/qualification-execution-envelopes.toml")
COMPONENTS_PATH = Path("contracts/components.toml")
SUMMARY_WORKFLOW = Path(".github/workflows/applicable-qualification.yml")
AUTHORITY_APPROVALS_PATH = Path(".github/qualification-authority-approvals.toml")
STABILITY_CONTRACT_PATH = Path("contracts/stability.toml")
V09_ROUTING_CONTRACT_PATH = Path("contracts/v09-qualification-routing.toml")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import v09_qualification_scope as v09_scope  # noqa: E402
HEX40 = re.compile(r"^[0-9a-f]{40}$")
GATE_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
SUPPORTED_CONCLUSIONS = {
    "success",
    "failure",
    "cancelled",
    "skipped",
    "timed_out",
    "action_required",
    "neutral",
    "stale",
    "startup_failure",
}


class QualificationError(RuntimeError):
    pass


# Per-decision snapshots. Never cache GitHub state across independent reads,
# reconciliations, requests, or positive second-pass verification.
_PR_FILE_BATCH: ContextVar[dict[tuple[str, int], list[dict[str, Any]]] | None] = ContextVar(
    "qualification_pr_file_batch", default=None,
)
_RUN_JOBS_BATCH: ContextVar[dict[tuple[str, int, int], list[dict[str, Any]]] | None] = ContextVar(
    "qualification_run_jobs_batch", default=None,
)
_READ_DEADLINE: ContextVar[float | None] = ContextVar(
    "qualification_read_deadline", default=None,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _read(root: Path, relative: str | Path) -> str:
    path = root / relative
    _require(
        path.is_file() and not path.is_symlink(),
        f"missing or unsafe repository file: {relative}",
    )
    return path.read_text(encoding="utf-8")


def _load_toml(root: Path, relative: str | Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(_read(root, relative))
    except tomllib.TOMLDecodeError as exc:
        raise QualificationError(f"invalid TOML {relative}: {exc}") from exc
    _require(isinstance(value, dict), f"TOML root must be a table: {relative}")
    return value


def _string_list(
    value: object, label: str, *, allow_empty: bool = False
) -> list[str]:
    _require(isinstance(value, list), f"{label} must be a list")
    _require(allow_empty or bool(value), f"{label} must not be empty")
    _require(
        all(
            isinstance(item, str) and item and item.strip() == item
            for item in value
        ),
        f"{label} contains invalid strings",
    )
    result = list(value)
    _require(len(result) == len(set(result)), f"{label} contains duplicates")
    return result


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile the GitHub path-pattern subset used by this repository."""
    _require(
        pattern and pattern.strip() == pattern,
        f"invalid empty/whitespace path pattern: {pattern!r}",
    )
    _require(
        "[" not in pattern
        and "]" not in pattern
        and "{" not in pattern
        and "}" not in pattern,
        f"unsupported path-pattern syntax requires reviewed matcher support: {pattern}",
    )
    result = "^"
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 1
                result += ".*"
            else:
                result += "[^/]*"
        elif char == "?":
            result += "[^/]"
        else:
            result += re.escape(char)
        index += 1
    return re.compile(result + "$")


def path_selected(path: str, patterns: list[str]) -> bool:
    _require(
        path and not path.startswith("/") and ".." not in Path(path).parts,
        f"unsafe changed path: {path!r}",
    )
    selected = False
    for raw in patterns:
        negative = raw.startswith("!")
        pattern = raw[1:] if negative else raw
        if _glob_regex(pattern).fullmatch(path) is not None:
            selected = not negative
    return selected


def _pull_request_paths(workflow: str) -> list[str] | None:
    """Extract the ordered pull_request.paths list from repository-owned YAML."""
    lines = workflow.splitlines()
    # Restrict YAML routing to the reviewed canonical mapping form.
    # Otherwise a quoted/duplicate key can shadow the routes extracted
    # here while GitHub executes another effective on.pull_request.paths.
    _require(
        not any(line.startswith(('"on":', "'on':", "<<:")) for line in lines)
        and sum(line == "on:" for line in lines) == 1,
        "workflow must have one canonical on: mapping",
    )
    events_start = lines.index("on:")
    events_end = next(
        (
            index for index in range(events_start + 1, len(lines))
            if lines[index] and not lines[index].startswith((" ", "#"))
        ),
        len(lines),
    )
    event_lines = lines[events_start + 1 : events_end]
    _require(
        not any(
            re.match(r"^  ['\\\"]?pull_request['\\\"]?:", line)
            and line != "  pull_request:"
            for line in event_lines
        ),
        "noncanonical pull_request event key",
    )
    _require(
        not any(line.startswith("  <<:") for line in event_lines)
        and event_lines.count("  pull_request:") <= 1,
        "duplicate pull_request event mapping",
    )
    if "  pull_request:" not in event_lines:
        return None
    event_index = lines.index("  pull_request:")
    event_end = next(
        (
            index for index in range(event_index + 1, events_end)
            if re.match(r"^  [^ #].*:", lines[index])
        ),
        events_end,
    )
    pr_lines = lines[event_index + 1 : event_end]
    _require(
        pr_lines.count("    paths:") <= 1
        and not any(
            re.match(r"^    ['\\\"]?paths['\\\"]?:", line)
            and line != "    paths:"
            for line in pr_lines
        )
        and not any(re.match(r"^    (?:<<|paths-ignore):", line) for line in pr_lines),
        "ambiguous pull_request path routing",
    )

    paths_index: int | None = None
    for index in range(event_index + 1, event_end):
        line = lines[index]
        if line == "    paths:":
            paths_index = index
            break
    if paths_index is None:
        return []

    patterns: list[str] = []
    for line in lines[paths_index + 1 : event_end]:
        if line.startswith("      #") or not line.strip():
            continue
        match = re.fullmatch(r'      - "([^"]+)"(?:\s+#.*)?', line)
        if match is None:
            break
        patterns.append(match.group(1))
    return patterns



def _push_paths(workflow: str) -> list[str] | None:
    """Read GitHub's reviewed on.push.paths subset, rejecting shadowed keys."""
    # First check the top-level on:/quoted shadow structure shared with PR routing.
    _pull_request_paths(workflow)
    lines = workflow.splitlines()
    on_idx = lines.index("on:")
    on_end = next(
        (idx for idx in range(on_idx + 1, len(lines))
         if lines[idx] and not lines[idx].startswith((" ", "#"))),
        len(lines),
    )
    events = lines[on_idx + 1:on_end]
    _require(
        events.count("  push:") <= 1
        and not any(
            re.match(r"""^  ['"]?push['"]?:""", line)
            and line != "  push:"
            for line in events
        ),
        "duplicate/noncanonical push event mapping",
    )
    if "  push:" not in events:
        return None
    start = lines.index("  push:")
    end = next(
        (idx for idx in range(start + 1, on_end)
         if re.match(r"^  [^ #].*:", lines[idx])),
        on_end,
    )
    push_lines = lines[start + 1:end]
    _require(
        push_lines.count("    paths:") <= 1
        and not any(
            re.match(r"""^    ['"]?paths['"]?:""", line)
            and line != "    paths:"
            for line in push_lines
        )
        and not any(
            re.match(r"^    (?:<<|paths-ignore):", line)
            for line in push_lines
        ),
        "ambiguous push path routing",
    )
    if "    paths:" not in push_lines:
        return []
    paths_index = lines.index("    paths:", start + 1, end)
    patterns: list[str] = []
    for line in lines[paths_index + 1:end]:
        if not line.strip() or line.startswith("      #"):
            continue
        match = re.fullmatch(r'      - "([^"]+)"(?:\s+#.*)?', line)
        if match is None:
            break
        patterns.append(match.group(1))
    _require(bool(patterns), "push path filter has no canonical entries")
    return patterns


def _workflow_name(workflow: str) -> str:
    match = re.search(r"(?m)^name:\s*(.+?)\s*$", workflow)
    _require(match is not None, "workflow lacks top-level name")
    return match.group(1).strip("'\"")


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    contract = _load_toml(root, CONTRACT_PATH)
    expected = {
        "schema_version",
        "id",
        "repository",
        "required_event",
        "summary_workflow",
        "summary_job",
        "branch_required_check",
        "mandatory_gate_ids",
        "routing_authority_paths",
        "native_only_components",
        "native_only_contracts",
        "release_workflows",
        "gate",
        "lane",
        "component",
        "contract",
    }
    _require(
        set(contract) == expected,
        "qualification-gate matrix fields changed without schema review",
    )
    _require(
        contract["schema_version"] == 1,
        "unsupported qualification-gate matrix schema",
    )
    _require(
        contract["id"] == "qualification/applicable-gates",
        "unexpected qualification-gate matrix id",
    )
    _require(
        contract["repository"] == "linura-org/linura",
        "unexpected repository identity",
    )
    _require(
        contract["required_event"] == "pull_request",
        "PR qualification event must remain pull_request",
    )
    _require(
        contract["summary_workflow"] == SUMMARY_WORKFLOW.as_posix(),
        "summary workflow identity drifted",
    )
    _require(
        contract["summary_job"] == "reconcile",
        "summary reconciliation job identity drifted",
    )
    _require(
        contract["branch_required_check"] == "applicable-qualification",
        "branch required-check identity drifted",
    )

    mandatory = _string_list(contract["mandatory_gate_ids"], "mandatory_gate_ids")
    _require(
        mandatory == ["canonical-ci", "security-rustsec", "codeql"],
        "mandatory native PR gate inventory changed without review",
    )
    _string_list(contract["routing_authority_paths"], "routing_authority_paths")
    _string_list(
        contract["native_only_components"],
        "native_only_components",
        allow_empty=True,
    )
    _string_list(
        contract["native_only_contracts"], "native_only_contracts", allow_empty=True
    )
    _string_list(contract["release_workflows"], "release_workflows")

    gates = contract["gate"]
    _require(isinstance(gates, list) and gates, "gate inventory is empty")
    gate_ids: set[str] = set()
    workflows: set[str] = set()
    base_gate_fields = {
        "id",
        "workflow",
        "workflow_name",
        "mandatory",
        "execution_lanes",
        "required_jobs",
        "paths",
    }
    v09_mode_fields = {
        "job_policy",
        "full_required_jobs",
        "regression_required_jobs",
    }
    for gate in gates:
        _require(isinstance(gate, dict), "gate must be a table")
        gate_id = gate.get("id")
        expected_fields = (
            base_gate_fields | v09_mode_fields
            if gate_id == "v09-qualification"
            else base_gate_fields
        )
        _require(
            set(gate) == expected_fields,
            f"gate fields changed without schema review: {gate_id}",
        )
        _require(
            isinstance(gate_id, str) and GATE_ID.fullmatch(gate_id) is not None,
            f"invalid gate id: {gate_id!r}",
        )
        _require(gate_id not in gate_ids, f"duplicate gate id: {gate_id}")
        gate_ids.add(gate_id)
        workflow = gate["workflow"]
        _require(
            isinstance(workflow, str)
            and workflow.startswith(".github/workflows/"),
            f"invalid gate workflow: {gate_id}",
        )
        _require(
            workflow not in workflows,
            f"workflow is assigned to multiple PR gates: {workflow}",
        )
        workflows.add(workflow)
        _require(
            isinstance(gate["workflow_name"], str) and gate["workflow_name"],
            f"missing workflow name: {gate_id}",
        )
        _require(
            isinstance(gate["mandatory"], bool),
            f"invalid mandatory flag: {gate_id}",
        )
        _string_list(gate["execution_lanes"], f"{gate_id}.execution_lanes")
        jobs = _string_list(gate["required_jobs"], f"{gate_id}.required_jobs")
        patterns = _string_list(
            gate["paths"], f"{gate_id}.paths", allow_empty=True
        )
        if gate["mandatory"]:
            _require(
                gate_id in mandatory,
                f"mandatory gate omitted from mandatory_gate_ids: {gate_id}",
            )
            _require(
                not patterns,
                f"mandatory native gate may not be path filtered: {gate_id}",
            )
        else:
            _require(
                gate_id not in mandatory,
                f"specialized gate cannot be marked mandatory: {gate_id}",
            )
            _require(patterns, f"specialized PR gate lacks path rules: {gate_id}")
        if gate_id == "v09-qualification":
            _require(
                gate["job_policy"] == "v09-full-vs-regression",
                "v0.9 job policy identity drifted",
            )
            full_jobs = _string_list(
                gate["full_required_jobs"],
                "v09-qualification.full_required_jobs",
            )
            regression_jobs = _string_list(
                gate["regression_required_jobs"],
                "v09-qualification.regression_required_jobs",
            )
            _require(
                not (set(jobs) & set(full_jobs))
                and not (set(jobs) & set(regression_jobs))
                and not (set(full_jobs) & set(regression_jobs)),
                "v0.9 conditional job groups overlap",
            )

    _require(
        {gate["id"] for gate in gates if gate["mandatory"]} == set(mandatory),
        "mandatory gate declarations do not match mandatory_gate_ids",
    )

    lanes = contract["lane"]
    _require(isinstance(lanes, list) and lanes, "lane inventory is empty")
    lane_ids: set[str] = set()
    for lane in lanes:
        _require(isinstance(lane, dict), "lane must be a table")
        _require(
            set(lane).issubset(
                {"id", "kind", "gate_id", "workflow", "entrypoint"}
            )
            and {"id", "kind"}.issubset(lane),
            "invalid lane fields",
        )
        lane_id = lane["id"]
        _require(
            isinstance(lane_id, str) and lane_id not in lane_ids,
            f"duplicate lane id: {lane_id}",
        )
        lane_ids.add(lane_id)
        _require(
            lane["kind"] in {"pr-gate", "release", "physical"},
            f"invalid lane kind: {lane_id}",
        )
        if lane["kind"] == "pr-gate":
            _require(
                lane.get("gate_id") in gate_ids
                and isinstance(lane.get("workflow"), str),
                f"PR lane lacks gate/workflow: {lane_id}",
            )
        elif lane["kind"] == "release":
            _require(
                isinstance(lane.get("workflow"), str) and "gate_id" not in lane,
                f"release lane shape invalid: {lane_id}",
            )
        else:
            _require(
                isinstance(lane.get("entrypoint"), str)
                and "gate_id" not in lane,
                f"physical lane shape invalid: {lane_id}",
            )

    components = contract["component"]
    _require(
        isinstance(components, list) and components,
        "component matrix is empty",
    )
    seen_components: set[str] = set()
    for item in components:
        _require(
            isinstance(item, dict) and set(item) == {"id", "path", "gates"},
            "invalid component matrix entry",
        )
        component_id = item["id"]
        _require(
            isinstance(component_id, str)
            and component_id not in seen_components,
            f"duplicate component: {component_id}",
        )
        seen_components.add(component_id)
        route = _string_list(
            item["gates"], f"component.{component_id}.gates", allow_empty=True
        )
        _require(
            all(gate in gate_ids for gate in route),
            f"component references unknown gate: {component_id}",
        )

    contract_items = contract["contract"]
    _require(
        isinstance(contract_items, list) and contract_items,
        "contract matrix is empty",
    )
    seen_contracts: set[str] = set()
    for item in contract_items:
        _require(
            isinstance(item, dict) and set(item) == {"path", "gates"},
            "invalid contract matrix entry",
        )
        path = item["path"]
        _require(
            isinstance(path, str) and path not in seen_contracts,
            f"duplicate contract: {path}",
        )
        seen_contracts.add(path)
        route = _string_list(
            item["gates"], f"contract.{path}.gates", allow_empty=True
        )
        _require(
            all(gate in gate_ids for gate in route),
            f"contract references unknown gate: {path}",
        )
    return contract


def _gates_by_id(
    contract: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    return {gate["id"]: gate for gate in contract["gate"]}


def required_gate_ids(
    contract: dict[str, Any], changed_paths: list[str]
) -> list[str]:
    # Tree-identical release-authorization PRs legitimately have no changed files.
    # An empty *successful* GitHub files response still requires all native gates.
    _require(
        isinstance(changed_paths, list)
        and all(isinstance(path, str) and bool(path) for path in changed_paths),
        "changed-path inventory must be a list of nonempty paths",
    )
    required = set(contract["mandatory_gate_ids"])
    for gate in contract["gate"]:
        if gate["mandatory"]:
            continue
        if any(path_selected(path, gate["paths"]) for path in changed_paths):
            required.add(gate["id"])
    return [
        gate["id"] for gate in contract["gate"] if gate["id"] in required
    ]


def validate_repository(
    root: Path = ROOT, contract: dict[str, Any] | None = None
) -> dict[str, Any]:
    contract = contract or load_contract(root)
    gates = _gates_by_id(contract)

    for gate in contract["gate"]:
        source = _read(root, gate["workflow"])
        _require(
            _workflow_name(source) == gate["workflow_name"],
            f"workflow name drift: {gate['id']}",
        )
        expected_run_name = (
            "run-name: \"${{ github.workflow }} :: ${{ github.event_name == 'pull_request' && format('PR{0} :: {1}', github.event.pull_request.number, github.sha) || (inputs.dispatch_nonce || github.sha) }}\"" if gate["mandatory"] else
            "run-name: '" + "${{ github.workflow }} :: PR${{ github.event.pull_request.number || 0 }} :: ${{ github.sha }}" + "'"
        )
        _require(
            re.findall(r"(?m)^run-name:[^\n]*$", source) == [expected_run_name],
            f"trusted PR event merge-SHA run-name drift: {gate['id']}",
        )
        paths = _pull_request_paths(source)
        if gate["mandatory"]:
            _require(
                paths == [],
                f"mandatory native workflow must be unfiltered: {gate['id']}",
            )
        else:
            _require(
                paths == gate["paths"],
                f"workflow routing differs from matrix: {gate['id']}",
            )
        push_paths = _push_paths(source)
        if push_paths:
            _require(
                push_paths == paths,
                f"push/PR qualification routing differs: {gate['id']}",
            )

    for path in contract["routing_authority_paths"]:
        _require(
            (root / path).is_file(), f"missing routing authority file: {path}"
        )
        for gate in contract["gate"]:
            if not gate["mandatory"]:
                _require(
                    not path_selected(path, gate["paths"]),
                    "routing authority unexpectedly fans out to specialized gate "
                    f"{gate['id']}: {path}",
                )

    summary = _read(root, contract["summary_workflow"])
    _require(
        "  pull_request_target:" in summary
        and "  workflow_run:" in summary
        and "workflow_dispatch" not in summary,
        "applicable-qualification summary must be event-driven",
    )
    _require(
        "    types: [opened, reopened, synchronize, edited, ready_for_review, closed]" in summary,
        "PR close event must refresh shared-head qualification",
    )
    _require(
        "  push:\n    branches: [main]" in summary
        and "    - cron: '17 * * * *'" in summary,
        "protected main base pushes and hourly recovery must refresh PR heads",
    )
    _require(
        "  affected-heads:" in summary
        and "  reconcile:" in summary
        and "      head_groups: ${{ steps.resolve.outputs.head_groups }}" in summary
        and "        group: ${{ fromJSON(needs.affected-heads.outputs.head_groups) }}" in summary
        and "      group: applicable-qualification-shard-${{ matrix.group.shard }}" in summary
        and "      queue: max" in summary
        and summary.count("      queue: max") == 1
        and "      cancel-in-progress: false" in summary
        and "  statuses: write" not in summary.split("  affected-heads:", 1)[1].split("  reconcile:", 1)[0],
        "head-derived matrix must serialize every status writer without write privilege during discovery",
    )
    for permission in (
        "actions: read",
        "contents: read",
        "pull-requests: read",
        "statuses: write",
    ):
        _require(
            permission in summary,
            f"summary workflow permission missing: {permission}",
        )
    workflow_block = re.search(
        r'(?ms)^    workflows:\n(?P<body>(?:      - "[^"]+"\n)+)    types: \[in_progress, completed\]$',
        summary,
    )
    _require(
        workflow_block is not None,
        "summary workflow_run inventory is malformed",
    )
    observed_workflows = set(
        re.findall(r'^      - "([^"]+)"$', workflow_block.group("body"), re.MULTILINE)
    )
    expected_workflows = {gate["workflow_name"] for gate in contract["gate"]}
    _require(
        observed_workflows == expected_workflows,
        "summary workflow_run inventory drifted",
    )
    _require(
        "ref: ${{ github.event.repository.default_branch }}" in summary
        and "python3 tools/applicable_qualification.py event-heads" in summary
        and "python3 tools/applicable_qualification.py reconcile-heads" in summary
        and '--heads-json "$HEAD_SHAS"' in summary
        and '--shard "$HEAD_SHARD"' in summary
        and '--retry-only "$RETRY_ONLY"' in summary
        and '--invalidate-only "$INVALIDATE_ONLY"' in summary
        and "INVALIDATE_ONLY: ${{ github.event_name == 'workflow_run' && github.event.action == 'in_progress' }}" in summary
        and "RETRY_ONLY: ${{ github.event_name == 'schedule' }}" in summary
        and "python3 tools/applicable_qualification.py verify-pr" not in summary
        and "--timeout-seconds" not in summary
        and "--poll-seconds" not in summary,
        "summary workflow must discover affected heads and reconcile using protected main code",
    )
    summary_job = re.escape(contract["summary_job"])
    _require(
        re.search(rf"(?m)^  {summary_job}:\s*$", summary) is not None
        and re.search(rf"(?m)^    name: {summary_job}\s*$", summary) is not None,
        "summary reconciliation job identity drifted",
    )


    envelope = _load_toml(root, ENVELOPE_CONTRACT_PATH)
    envelope_ids = {lane["id"] for lane in envelope.get("lane", [])}
    matrix_ids = {lane["id"] for lane in contract["lane"]}
    _require(
        matrix_ids == envelope_ids,
        "execution-lane inventory drifted: "
        f"missing={sorted(envelope_ids - matrix_ids)} "
        f"extra={sorted(matrix_ids - envelope_ids)}",
    )
    envelope_workflows = {
        lane["id"]: lane.get("workflow") for lane in envelope["lane"]
    }
    envelope_entrypoints = {
        lane["id"]: lane.get("entrypoint") for lane in envelope["lane"]
    }
    for lane in contract["lane"]:
        if lane["kind"] == "pr-gate":
            gate = gates[lane["gate_id"]]
            _require(
                lane["workflow"] == envelope_workflows[lane["id"]],
                f"execution-lane workflow drift: {lane['id']}",
            )
            _require(
                lane["id"] in gate["execution_lanes"],
                f"gate execution-lane inventory missing: {lane['id']}",
            )
        elif lane["kind"] == "release":
            _require(
                lane["workflow"] == envelope_workflows[lane["id"]],
                f"release lane workflow drift: {lane['id']}",
            )
        else:
            _require(
                lane["entrypoint"] == envelope_entrypoints[lane["id"]],
                f"physical lane entrypoint drift: {lane['id']}",
            )

    for workflow in contract["release_workflows"]:
        _require(
            (root / workflow).is_file(),
            f"release workflow inventory references missing file: {workflow}",
        )

    components = _load_toml(root, COMPONENTS_PATH).get("component", [])
    component_by_id = {item["id"]: item for item in components}
    matrix_components = {
        item["id"]: item for item in contract["component"]
    }
    _require(
        set(matrix_components) == set(component_by_id),
        "component qualification matrix is not exhaustive",
    )
    native_only_components = set(contract["native_only_components"])
    for component_id, component in component_by_id.items():
        matrix = matrix_components[component_id]
        _require(
            matrix["path"] == component["path"],
            f"component path drift: {component_id}",
        )
        probe = (
            component["path"].rstrip("/")
            + "/__qualification_route_probe__.rs"
        )
        selected = [
            gate["id"]
            for gate in contract["gate"]
            if not gate["mandatory"]
            and path_selected(probe, gate["paths"])
        ]
        _require(
            matrix["gates"] == selected,
            f"component gate map drift: {component_id}",
        )
        if component_id in native_only_components:
            _require(
                not selected,
                "native-only component unexpectedly has specialized route: "
                f"{component_id}",
            )
        else:
            _require(
                bool(selected),
                "active component has no specialized qualification route: "
                f"{component_id}",
            )
    _require(
        native_only_components.issubset(component_by_id),
        "native_only_components references unknown component",
    )

    repository_contracts = {
        path.relative_to(root).as_posix()
        for path in (root / "contracts").glob("*.toml")
        if path.is_file() and not path.is_symlink()
    }
    stability = _load_toml(root, STABILITY_CONTRACT_PATH)
    registered = stability.get("contract")
    _require(
        isinstance(registered, list) and registered,
        "stability contract registry is empty",
    )
    registered_ids: set[str] = set()
    registered_paths: set[str] = set()
    for item in registered:
        _require(isinstance(item, dict), "invalid stability contract entry")
        contract_id = item.get("id")
        path = item.get("path")
        _require(
            isinstance(contract_id, str)
            and contract_id
            and contract_id not in registered_ids,
            f"duplicate or invalid registered contract id: {contract_id!r}",
        )
        _require(
            isinstance(path, str)
            and path
            and not path.startswith("/")
            and ".." not in Path(path).parts
            and path not in registered_paths,
            f"duplicate or unsafe registered contract path: {path!r}",
        )
        registered_ids.add(contract_id)
        registered_paths.add(path)
        registered_path = root / path
        _require(
            registered_path.is_file() and not registered_path.is_symlink(),
            f"registered contract path is missing or unsafe: {path}",
        )
    repository_contracts |= registered_paths

    matrix_contracts = {
        item["path"]: item for item in contract["contract"]
    }
    _require(
        set(matrix_contracts) == repository_contracts,
        "contract qualification matrix is not exhaustive: "
        f"missing={sorted(repository_contracts - set(matrix_contracts))} "
        f"extra={sorted(set(matrix_contracts) - repository_contracts)}",
    )
    native_only_contracts = set(contract["native_only_contracts"])
    _require(
        native_only_contracts.issubset(repository_contracts),
        "native_only_contracts references unknown contract",
    )
    for path in sorted(repository_contracts):
        selected = [
            gate["id"]
            for gate in contract["gate"]
            if not gate["mandatory"]
            and path_selected(path, gate["paths"])
        ]
        _require(
            matrix_contracts[path]["gates"] == selected,
            f"contract gate map drift: {path}",
        )
        if path in native_only_contracts:
            _require(
                not selected,
                "native-only contract unexpectedly has specialized route: "
                f"{path}",
            )
        else:
            _require(
                bool(selected),
                f"active contract has no specialized qualification route: {path}",
            )

    # Approvals are read exclusively from protected default-branch code.
    # The ledger is itself non-executable; changed PR ledger content is ignored.
    _approved_gate_bundles(root)
    return {
        "schema_version": contract["schema_version"],
        "ready": True,
        "mandatory_gate_ids": contract["mandatory_gate_ids"],
        "specialized_gate_ids": [
            gate["id"] for gate in contract["gate"] if not gate["mandatory"]
        ],
        "execution_lanes": [lane["id"] for lane in contract["lane"]],
    }


def _api_json(url: str, token: str) -> Any:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "linura-applicable-qualification/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    timeout = 30.0
    deadline = _READ_DEADLINE.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        _require(remaining > 2.0, "read-only decision exceeded the 115-second API budget")
        timeout = min(timeout, remaining - 1.0)
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise QualificationError(
            f"GitHub API {exc.code} for {url}: {body[:300]}"
        ) from exc
    except URLError as exc:
        raise QualificationError(
            f"GitHub API unavailable for {url}: {exc}"
        ) from exc


def _post_json(url: str, token: str, payload: dict[str, Any]) -> Any:
    """Bounded retries for idempotent status posts; no atomic-CAS claim."""
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request = Request(
        url,
        data=data,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "linura-applicable-qualification/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    for attempt in range(3):
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            retry = exc.code in {429, 500, 502, 503, 504}
            if exc.code == 403 and exc.headers is not None:
                retry = (
                    exc.headers.get("X-RateLimit-Remaining") != "0"
                    and exc.headers.get("Retry-After") is not None
                )
            if retry and attempt < 2:
                delay = float(attempt + 1)
                header = exc.headers.get("Retry-After") if exc.headers else None
                if header is not None:
                    try:
                        delay = min(5.0, max(delay, float(header)))
                    except ValueError:
                        pass
                time.sleep(delay)
                continue
            raise QualificationError(
                f"GitHub API {exc.code} for {url}: {body[:300]}"
            ) from exc
        except URLError as exc:
            if attempt < 2:
                time.sleep(float(attempt + 1))
                continue
            raise QualificationError(
                f"GitHub API unavailable for {url}: {exc}"
            ) from exc
    raise QualificationError(f"GitHub status publication unavailable: {url}")


def _paged(
    url: str, token: str, *, collection_key: str | None = None
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    page = 1
    while True:
        separator = "&" if "?" in url else "?"
        payload = _api_json(
            f"{url}{separator}per_page=100&page={page}", token
        )
        if collection_key is None:
            _require(
                isinstance(payload, list),
                f"expected GitHub list response: {url}",
            )
            page_values = payload
        else:
            _require(
                isinstance(payload, dict)
                and isinstance(payload.get(collection_key), list),
                f"expected GitHub collection {collection_key}: {url}",
            )
            page_values = payload[collection_key]
        _require(
            all(isinstance(item, dict) for item in page_values),
            f"malformed GitHub list entry: {url}",
        )
        values.extend(page_values)
        if len(page_values) < 100:
            break
        if page == 30 and collection_key is None and re.fullmatch(
            r"https://api\.github\.com/repos/[^/]+/[^/]+/pulls/[0-9]+/files",
            url,
        ) is not None:
            # GitHub documents at most 3,000 PR files. Only this particular
            # endpoint has a hard 30-page cap; PR discovery must not truncate.
            break
        page += 1
        _require(page <= 10000, f"unbounded GitHub pagination: {url}")
    return values


def _pr_changed_paths(
    repository: str, pr_number: int, token: str, *,
    include_rename_sources: bool = False,
) -> list[str]:
    cache = _PR_FILE_BATCH.get()
    cache_key = (repository, pr_number)
    if cache is not None and cache_key in cache:
        files = cache[cache_key]
    else:
        files = _paged(
            f"https://api.github.com/repos/{repository}/pulls/{pr_number}/files",
            token,
        )
        if cache is not None:
            cache[cache_key] = files
    changed: set[str] = set()
    for item in files:
        filename = item.get("filename")
        _require(
            isinstance(filename, str) and filename,
            "PR file entry lacks filename",
        )
        # GitHub's pull_request.paths filter uses the changed-file entry's
        # filename. For a rename it is the destination, not previous_filename.
        # Using the old source here can demand a gate that GitHub never ran.
        changed.add(filename)
        if include_rename_sources and item.get("status") == "renamed":
            old_name = item.get("previous_filename")
            _require(
                isinstance(old_name, str) and bool(old_name),
                "renamed PR file lacks previous_filename for v0.9 no-rename scope",
            )
            changed.add(old_name)
    # The GitHub files API returns [] for tree-identical authorization PRs.
    # Unlike a failed API request, that is an authoritative empty inventory.
    return sorted(changed)


def _workflow_path_matches(run_path: object, expected_path: str) -> bool:
    """Match the exact workflow file with GitHub's optional @ref suffix.

    GitHub workflow_run.path can be `.github/workflows/ci.yml@main`
    rather than the bare matrix path. Reject malformed suffixes and never
    use a prefix match for the workflow file itself.
    """
    if not isinstance(run_path, str):
        return False
    path, separator, ref = run_path.partition("@")
    if path != expected_path:
        return False
    if not separator:
        return True
    if not ref:
        return False
    if any(
        ord(char) < 33 or ord(char) == 127 or char in "\\~^:?*["
        for char in ref
    ):
        return False
    if ".." in ref or "@{" in ref or ref.endswith("."):
        return False
    return not any(
        part in ("", ".", "..")
        or part.startswith(".")
        or part.endswith(".lock")
        for part in ref.split("/")
    )


def _pr_base_identity(pr: dict[str, Any]) -> tuple[str, str, int]:
    base = pr.get("base")
    _require(isinstance(base, dict), "PR base metadata missing")
    base_repo = base.get("repo")
    _require(isinstance(base_repo, dict), "PR base repository missing")
    ref, sha, repo_id = base.get("ref"), base.get("sha"), base_repo.get("id")
    _require(
        isinstance(ref, str) and bool(ref)
        and isinstance(sha, str) and HEX40.fullmatch(sha) is not None
        and isinstance(repo_id, int) and repo_id > 0,
        "PR base identity incomplete",
    )
    return (ref, sha, repo_id)


def _reviewed_test_merge(repository: str, pr: dict[str, Any], head_sha: str, token: str) -> str:
    """Prove immutable PR-event test-merge parents, never mutable run PR associations."""
    _require(pr.get("state", "open") == "open", "qualification PR is not open")
    base_ref, base_sha, _ = _pr_base_identity(pr)
    _require(base_ref == "main", "qualification base must be protected main")
    merge_sha = pr.get("merge_commit_sha")
    _require(isinstance(merge_sha, str) and HEX40.fullmatch(merge_sha) is not None,
             "PR synthetic test-merge commit unavailable")
    commit = _api_json(f"https://api.github.com/repos/{repository}/commits/{merge_sha}", token)
    _require(isinstance(commit, dict) and commit.get("sha") == merge_sha
             and isinstance(commit.get("parents"), list)
             and len(commit["parents"]) == 2
             and [p.get("sha") if isinstance(p, dict) else None for p in commit["parents"]]
             == [base_sha, head_sha],
             "PR synthetic merge parents do not match current base/head")
    return merge_sha


def _reviewed_run_merge_sha(
    run: dict[str, Any], gate: dict[str, Any], pr_number: int,
) -> str | None:
    title = run.get("display_title")
    prefix = gate["workflow_name"] + " :: PR" + str(pr_number) + " :: "
    if not isinstance(title, str) or not title.startswith(prefix):
        return None
    sha = title[len(prefix):]
    return sha if HEX40.fullmatch(sha) is not None else None


def _run_matches(
    run: dict[str, Any], *, gate: dict[str, Any], head_sha: str,
    pr_number: int, pr_base: tuple[str, str, int],
    merge_sha: str | None = None,
) -> bool:
    """Only the event-derived immutable synthetic SHA proves historical base."""
    if (not _workflow_path_matches(run.get("path"), gate["workflow"])
        or run.get("event") != "pull_request"
        or run.get("head_sha") != head_sha
        or merge_sha is None
        or _reviewed_run_merge_sha(run, gate, pr_number) != merge_sha):
        return False
    # PR identity is bound by GitHub's original event-derived title. The
    # mutable pull_requests association is deliberately not authorization.
    return True


def _has_stale_pr_base_run(
    runs: list[dict[str, Any]], *, gate: dict[str, Any],
    head_sha: str, pr_number: int, pr_base: tuple[str, str, int],
    merge_sha: str | None = None,
) -> bool:
    """Detect older event-derived synthetic merge SHAs, never accept them."""
    for run in runs:
        if (run.get("event") != "pull_request"
            or run.get("head_sha") != head_sha
            or not _workflow_path_matches(run.get("path"), gate["workflow"])):
            continue
        historical = _reviewed_run_merge_sha(run, gate, pr_number)
        if historical is not None and historical != merge_sha:
            return True
    return False


def _newest_matching_run(
    runs: list[dict[str, Any]],
    *,
    gate: dict[str, Any],
    head_sha: str,
    pr_number: int,
    pr_base: tuple[str, str, int],
    merge_sha: str | None = None,
) -> dict[str, Any] | None:
    matching = [
        run for run in runs
        if _run_matches(
            run,
            gate=gate,
            head_sha=head_sha,
            pr_number=pr_number,
            pr_base=pr_base, merge_sha=merge_sha,
        )
    ]
    if not matching:
        return None
    return max(
        matching,
        key=lambda run: (
            int(run.get("run_number") or 0),
            int(run.get("run_attempt") or 0),
            int(run.get("id") or 0),
        ),
    )


def _head_runs(
    repository: str, head_sha: str, token: str
) -> list[dict[str, Any]]:
    params = urlencode({"head_sha": head_sha})
    return _paged(
        f"https://api.github.com/repos/{repository}/actions/runs?{params}",
        token,
        collection_key="workflow_runs",
    )


def _v09_job_mode(root: Path, changed_paths: list[str]) -> str:
    routing = _load_toml(root, V09_ROUTING_CONTRACT_PATH)
    try:
        full = v09_scope.requires_full_qualification(changed_paths, routing)
    except v09_scope.RoutingError as exc:
        raise QualificationError(
            f"v0.9 qualification routing is invalid: {exc}"
        ) from exc
    return "full" if full else "regression"


def _verify_required_jobs(
    repository: str,
    gate: dict[str, Any],
    run: dict[str, Any],
    token: str,
    *,
    root: Path,
    changed_paths: list[str],
) -> str:
    cache = _RUN_JOBS_BATCH.get()
    cache_key = (repository, int(run["id"]), int(run.get("run_attempt") or 1))
    if cache is not None and cache_key in cache:
        jobs = cache[cache_key]
    else:
        jobs = _paged(
            "https://api.github.com/repos/"
            f"{repository}/actions/runs/{int(run['id'])}/jobs?filter=latest",
            token,
            collection_key="jobs",
        )
        if cache is not None:
            cache[cache_key] = jobs
    named = [job for job in jobs if isinstance(job.get("name"), str)]
    names = [job["name"] for job in named]
    _require(
        len(names) == len(set(names)),
        f"{gate['id']}: duplicate GitHub job names are ambiguous",
    )
    by_name = {job["name"]: job for job in named}

    def require_success(required: list[str], label: str) -> None:
        missing = sorted(set(required) - set(by_name))
        _require(
            not missing,
            f"{gate['id']}: required {label} job absent: {missing}",
        )
        for name in required:
            job = by_name[name]
            _require(
                job.get("status") == "completed"
                and job.get("conclusion") == "success",
                f"{gate['id']}: required {label} job {name} is "
                f"{job.get('status')}/{job.get('conclusion')}",
            )

    require_success(gate["required_jobs"], "qualification")
    if gate.get("job_policy") != "v09-full-vs-regression":
        return "all-success"

    mode = _v09_job_mode(root, changed_paths)
    mode_jobs = (
        gate["full_required_jobs"]
        if mode == "full"
        else gate["regression_required_jobs"]
    )
    require_success(mode_jobs, f"v0.9 {mode}")
    return f"v09-{mode}"



def _trusted_gate_script_paths(
    root: Path, contract: dict[str, Any],
) -> set[str]:
    """Inventory direct and transitive first-party gate executables.

    Only trusted default-branch sources are parsed; PR content is never
    executed or imported into this authority process. Both shell script
    references and Python module imports are followed recursively.
    """
    initial = {
        *(gate["workflow"] for gate in contract["gate"]),
        contract["summary_workflow"],
        "tools/check_validation_gates.py",
        "scripts/check_repository.py",
        "scripts/lint_github_workflows.sh",
        "tools/applicable_qualification.py",
        "tools/qualification_evidence.py",
        "tools/qualification_evidence_verifiers.py",
        "tools/qualification_envelope.py",
        "tests/tooling/test_applicable_qualification.py",
        "tests/tooling/test_qualification_evidence.py",
        "tests/tooling/test_validation_gates.py",
    }
    # An executable local reusable workflow may run on the PR merge ref,
    # even when it is not itself a top-level matrix gate. Inspect all reviewed
    # workflow definitions, not only root workflows declared in the matrix.
    workflows = root / ".github/workflows"
    if workflows.is_dir():
        initial.update(
            path.relative_to(root).as_posix()
            for path in workflows.glob("*.yml")
            if path.is_file() and not path.is_symlink()
        )
        initial.update(
            path.relative_to(root).as_posix()
            for path in workflows.glob("*.yaml")
            if path.is_file() and not path.is_symlink()
        )
    actions = root / ".github/actions"
    if actions.is_dir():
        initial.update(
            path.relative_to(root).as_posix()
            for path in actions.rglob("action.yml")
            if path.is_file() and not path.is_symlink()
        )
    found: set[str] = set()
    queue = sorted(initial)
    # Workflows invoke unittest targets by dotted module identity, not just
    # slash-form file paths. A modified test module is executable gate code:
    # even an empty test suite can report success.
    reference = re.compile(
        r"(?:tools|scripts|tests|qualification|bindings/python/tests)/"
        r"[A-Za-z0-9_./-]+\.(?:py|sh|env|c|xml)"
    )
    dotted_reference = re.compile(
        r"\b(?:tools|scripts|tests)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b"
    )
    for relative in queue:
        if relative in found:
            continue
        _require(
            len(found) < 1024,
            "trusted gate source graph exceeds safe static inspection bound",
        )
        candidate = Path(relative)
        _require(
            not candidate.is_absolute() and ".." not in candidate.parts,
            f"unsafe trusted gate source: {relative}",
        )
        path = root / candidate
        if not path.is_file() or path.is_symlink():
            # Some references occur in test fixtures or explanatory comments.
            # Only executable files in the reviewed tree can be followed.
            continue
        found.add(relative)
        contents = path.read_text(encoding="utf-8")
        dependencies = set(reference.findall(contents))
        # Resolve dotted unittest targets and module imports from the reviewed
        # filesystem, walking backwards to support Class.method selectors.
        # Do not execute or import contributor-controlled test code.
        for dotted in dotted_reference.findall(contents):
            parts = dotted.split(".")
            for size in range(len(parts), 1, -1):
                module_file = "/".join(parts[:size]) + ".py"
                candidate_file = root / module_file
                if candidate_file.is_file() and not candidate_file.is_symlink():
                    dependencies.add(module_file)
                    break
        if relative.endswith(".py"):
            try:
                syntax = ast.parse(contents, filename=relative)
            except SyntaxError as exc:
                raise QualificationError(
                    f"trusted gate Python source is invalid: {relative}"
                ) from exc
            for node in ast.walk(syntax):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules = [node.module]
                    if node.module.split(".", 1)[0] in ("tools", "scripts", "tests"):
                        modules.extend(
                            node.module + "." + alias.name
                            for alias in node.names
                        )
                for module in modules:
                    if module.startswith(("tools.", "scripts.", "tests.")):
                        dependencies.add(module.replace(".", "/") + ".py")
        for dependency in sorted(dependencies):
            dep = Path(dependency)
            if (
                dep.is_absolute() or ".." in dep.parts
                or dependency in found or dependency in queue
            ):
                continue
            if (root / dep).is_file() and not (root / dep).is_symlink():
                queue.append(dependency)
    return found


def _untrusted_gate_definition_edits(
    contract: dict[str, Any], paths: list[str], *,
    root: Path = ROOT,
) -> list[str]:
    """Reject all changed first-party gate sources, including dependencies.

    Reviewing workflow YAML alone does not establish that the scripts it
    invokes still perform the reviewed qualification. The source graph is
    determined from protected base code, never a PR-controlled manifest.
    """
    trusted = _trusted_gate_script_paths(root, contract)
    trusted.update({
        "contracts/qualification-gate-matrix.toml",
        "contracts/qualification-evidence-binding.toml",
        "contracts/qualification-execution-envelopes.toml",
        "tools/qualification_guest_identity.py",
    })
    return sorted({
        path for path in paths
        if (
            path in trusted
            or path.startswith(".github/workflows/")
            or path.startswith(".github/actions/")
            or path.startswith("tools/xtask/")
            # Local VM/physical harness code and fixtures are themselves
            # qualification authority, including newly added files not yet
            # visible to a protected-base reference graph. Classify the full
            # tree rather than enumerating historical script filenames.
            or path.startswith("qualification/")
            # VM/host acceptance cases are executable assertions and
            # provisioning fixtures, not inert documentation. Protect new
            # and modified JSON, systemd and udev inputs alike.
            or path.startswith("tests/acceptance/")
            or path.startswith("services/qualification-publisher/")
            # Python startup hooks and module shadows can execute before
            # the verifier imports its reviewed helpers. New paths are
            # absent from the protected-base import graph: classify them
            # by execution search path instead of relying on discovery.
            # ROOT and the direct tools/scripts invocation directories
            # can be sys.path entries for the trusted verifier or gates.
            or ("/" not in path and path.endswith((".py", ".pyc", ".so", ".pyd")))
            or (path.startswith(("tools/", "scripts/"))
                and path.endswith((".py", ".pyc", ".so", ".pyd")))
            # Modules can gain implicit package execution by adding an
            # initializer, including in previously absent packages.
            or (re.search(r"/__init__(?:\.[^/]+)?\.(?:py|pyc|so|pyd)$", path)
                is not None
                and (
                    len(Path(path).parts) == 2
                    or path.startswith((
                        "tests/", "qualification/", "bindings/python/tests/",
                    ))
                ))
            or (path.endswith(("/sitecustomize.py", "/usercustomize.py"))
                or path in {"sitecustomize.py", "usercustomize.py"})

            # Canonical xtask discovers all tests/tooling/test_*.py; both
            # canonical CI and Codex discover bindings/python/tests/test_*.py.
            # Include new modules and their helpers, which do not yet exist
            # in the protected-base dependency graph.
            or (path.startswith("tests/tooling/") and path.endswith(".py"))
            or (path.startswith("bindings/python/tests/") and path.endswith(".py"))
            or path.startswith(".cargo/")
            or path in {
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                "tools/codex/versions.env",
            }
        )
    })


def _approved_gate_bundles(root: Path) -> dict[str, tuple[int, str]]:
    """Read protected approvals; reviewer identity and solo modes are distinct."""
    document = _load_toml(root, AUTHORITY_APPROVALS_PATH)
    _require(
        set(document).issubset({"schema_version", "solo_operator", "approval"})
        and document.get("schema_version") == 1
        and isinstance(document.get("solo_operator"), str)
        and re.fullmatch(r"[A-Za-z0-9-]{1,39}", document["solo_operator"]) is not None,
        "invalid protected authority-approval ledger",
    )
    approvals = document.get("approval", [])
    _require(isinstance(approvals, list), "authority approvals must be a list")
    result: dict[str, tuple[int, str]] = {}
    for entry in approvals:
        _require(
            isinstance(entry, dict)
            and set(entry) == {
                "bundle_sha256", "review_pr", "rationale", "approval_mode",
            },
            "authority approval entry has unreviewed fields",
        )
        mode = entry["approval_mode"]
        _require(
            mode in ("independent-review", "solo-operator"),
            "authority approval mode is not reviewed",
        )
        digest = entry["bundle_sha256"]
        _require(
            isinstance(digest, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
            and digest not in result,
            "duplicate or malformed authority approval digest",
        )
        _require(
            isinstance(entry["review_pr"], int) and entry["review_pr"] > 0
            and isinstance(entry["rationale"], str)
            and bool(entry["rationale"].strip()),
            "authority approval needs independent PR traceability and rationale",
        )
        result[digest] = (entry["review_pr"], mode)
    return result


def _authority_bundle_digest(
    repository: str, pr_number: int, token: str, paths: list[str],
    *, pr: dict[str, Any] | None = None,
) -> str:
    """Bind a reviewed whole-PR diff to its PR head and prior blob identities.

    Base commit SHAs are intentionally not in the digest: the ledger-only
    approval must merge into main before the code PR qualifies. An unrelated
    main update may advance the base without changing the meaning of the
    reviewed edit. Each changed path's *previous* Git tree entry is bound
    instead, so a later security fix C cannot reuse approval for A -> B to
    authorize C -> B. The code PR number forbids cross-PR replay. Do not
    bind the contributor head SHA: merging the required approval ledger PR
    advances main, and strict up-to-date protection forces a new contributor
    head for the exact same reviewed diff. Binding that head would create
    an endless ledger-approval/rebase cycle. Missing or incomplete base-tree
    evidence denies; actual qualification still binds the final exact head.
    """
    if pr is None:
        pr = _api_json(
            f"https://api.github.com/repos/{repository}/pulls/{pr_number}", token,
        )
    _require(isinstance(pr, dict), "authority PR metadata missing")
    head = pr.get("head")
    _require(
        isinstance(head, dict)
        and isinstance(head.get("sha"), str)
        and HEX40.fullmatch(head["sha"]) is not None
        and pr.get("number") == pr_number,
        "authority approval requires exact code PR/head identity",
    )
    base = pr.get("base")
    base_repo = base.get("repo") if isinstance(base, dict) else None
    _require(
        isinstance(base, dict)
        and base.get("ref") == "main"
        and isinstance(base.get("sha"), str)
        and HEX40.fullmatch(base["sha"]) is not None
        and isinstance(base_repo, dict)
        and base_repo.get("full_name") == repository,
        "authority approval requires exact protected base identity",
    )
    files = _paged(
        f"https://api.github.com/repos/{repository}/pulls/{pr_number}/files",
        token,
    )
    # A Git commit SHA is not its tree SHA; prove the immutable link.
    base_commit = _api_json(
        f"https://api.github.com/repos/{repository}/git/commits/"
        f"{base['sha']}", token,
    )
    base_tree = base_commit.get("tree") if isinstance(base_commit, dict) else None
    _require(
        isinstance(base_commit, dict)
        and base_commit.get("sha") == base["sha"]
        and isinstance(base_tree, dict)
        and isinstance(base_tree.get("sha"), str)
        and HEX40.fullmatch(base_tree["sha"]) is not None,
        "authority base commit/tree identity unavailable",
    )
    tree_sha = base_tree["sha"]
    tree = _api_json(
        f"https://api.github.com/repos/{repository}/git/trees/"
        f"{tree_sha}?recursive=1", token,
    )
    _require(
        isinstance(tree, dict)
        and tree.get("sha") == tree_sha
        and tree.get("truncated") is False
        and isinstance(tree.get("tree"), list),
        "authority base tree incomplete or unavailable",
    )
    old_entries: dict[str, dict[str, str]] = {}
    for item in tree["tree"]:
        _require(isinstance(item, dict), "malformed authority base tree")
        path, blob, mode, kind = (
            item.get("path"), item.get("sha"), item.get("mode"), item.get("type"),
        )
        _require(
            isinstance(path, str) and bool(path)
            and path not in old_entries
            and isinstance(blob, str) and HEX40.fullmatch(blob) is not None
            and isinstance(mode, str) and bool(mode)
            and kind in ("blob", "tree", "commit"),
            "ambiguous or invalid authority base tree entry",
        )
        old_entries[path] = {"sha": blob, "mode": mode, "type": kind}

    authority = set(paths)
    covered: set[str] = set()
    entries: list[dict[str, Any]] = []
    for file in files:
        _require(isinstance(file, dict), "malformed authority PR file entry")
        affected = {file.get("filename")}
        if file.get("status") == "renamed":
            affected.add(file.get("previous_filename"))
        covered.update(affected & authority)
        name, status, blob = (
            file.get("filename"), file.get("status"), file.get("sha")
        )
        _require(
            isinstance(name, str) and bool(name)
            and isinstance(status, str)
            and status in {"added", "modified", "removed", "renamed", "changed", "copied"}
            and isinstance(blob, str)
            and HEX40.fullmatch(blob) is not None,
            "authority PR file identity unavailable or malformed",
        )
        previous = old_entries.get(name)
        if status == "added":
            _require(
                previous is None,
                f"authority previous file identity contradicts {status}: {name}",
            )
        elif status in ("modified", "removed", "changed"):
            _require(
                previous is not None and previous["type"] != "tree",
                f"authority previous file identity missing for {status}: {name}",
            )
        record: dict[str, Any] = {
            "path": name, "status": status, "blob": blob,
            "previous": previous,
        }
        if status in ("renamed", "copied"):
            former = file.get("previous_filename")
            _require(
                isinstance(former, str) and bool(former)
                and former != name and former in old_entries
                and old_entries[former]["type"] != "tree",
                "authority rename/copy source identity missing",
            )
            record["previous_filename"] = former
            record["previous_source"] = old_entries[former]
        entries.append(record)
    _require(
        covered == authority
        and len({entry["path"] for entry in entries}) == len(entries),
        "approved authority bundle does not cover the full PR authority delta",
    )
    payload = {
        "schema_version": 2,
        "repository": repository,
        "pr_number": pr_number,
        "files": sorted(entries, key=lambda entry: entry["path"]),
    }
    return "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _verify_ledger_native_checks(
    *, root: Path, contract: dict[str, Any], repository: str,
    approval_pr: int, approval: dict[str, Any], token: str,
) -> bool:
    """Bind original native gates to immutable pre-approval-merge main.

    Mutable workflow-run PR associations cannot establish the tested base.
    Compare native synthetic-merge parents with the actual protected-main
    approval merge commit's immutable first parent. A PR merged using an
    unsupported method denies solo approval rather than guessing.
    """
    try:
        head = approval["head"]["sha"]
        merged_sha = approval["merge_commit_sha"]
        _require(isinstance(head, str) and HEX40.fullmatch(head) is not None
                 and isinstance(merged_sha, str)
                 and HEX40.fullmatch(merged_sha) is not None,
                 "ledger approval missing immutable merge identities")
        merged = _api_json(
            f"https://api.github.com/repos/{repository}/commits/{merged_sha}", token)
        _require(isinstance(merged, dict) and merged.get("sha") == merged_sha
                 and isinstance(merged.get("parents"), list)
                 and bool(merged["parents"])
                 and isinstance(merged["parents"][0], dict)
                 and HEX40.fullmatch(merged["parents"][0].get("sha", "")) is not None,
                 "ledger merge parent unavailable")
        historical_base = merged["parents"][0]["sha"]
        runs = _head_runs(repository, head, token)
        gates = _gates_by_id(contract)
        proven_merges: set[str] = set()
        for gate_id in contract["mandatory_gate_ids"]:
            gate = gates[gate_id]
            possible = [run for run in runs
                if run.get("event") == "pull_request"
                and run.get("head_sha") == head
                and _workflow_path_matches(run.get("path"), gate["workflow"])
                and _reviewed_run_merge_sha(run, gate, approval_pr) is not None]
            if not possible:
                return False
            run = max(possible, key=lambda r: (
                int(r.get("run_number") or 0),
                int(r.get("run_attempt") or 0),
                int(r.get("id") or 0),
            ))
            run_merge = _reviewed_run_merge_sha(run, gate, approval_pr)
            if run_merge is None:
                return False
            if run_merge not in proven_merges:
                synthetic = _api_json(
                    f"https://api.github.com/repos/{repository}/commits/{run_merge}",
                    token,
                )
                _require(isinstance(synthetic, dict)
                         and synthetic.get("sha") == run_merge
                         and isinstance(synthetic.get("parents"), list)
                         and len(synthetic["parents"]) == 2
                         and [p.get("sha") if isinstance(p, dict) else None
                              for p in synthetic["parents"]]
                         == [historical_base, head],
                         "ledger native run did not test the merged base/head")
                proven_merges.add(run_merge)
            if (run.get("status") != "completed"
                or run.get("conclusion") != "success"):
                return False
            _verify_required_jobs(
                repository, gate, run, token, root=root,
                changed_paths=[AUTHORITY_APPROVALS_PATH.as_posix()],
            )
    except (QualificationError, KeyError, TypeError, ValueError):
        return False
    return True


def _independently_reviewed_authority_upgrade(
    repository: str, approval_pr: int, code_pr: int,
    bundle_digest: str, token: str, *,
    code_author: str, approval_mode: str, solo_operator: str,
    root: Path = ROOT, contract: dict[str, Any] | None = None,
) -> bool:
    """Check separate, exact-bundle approval with explicit human authority.

    independent-review: a real reviewer different from BOTH authors.
    solo-operator: protected-main operator decision, independently executed
    original native gates on the separate ledger-only approval PR. This
    is NOT claimed to constitute independent human code review.
    """
    if approval_pr == code_pr or not code_author:
        return False
    approval = _api_json(
        f"https://api.github.com/repos/{repository}/pulls/{approval_pr}", token,
    )
    _require(isinstance(approval, dict), "approval PR metadata missing")
    base, head, author = (
        approval.get("base"), approval.get("head"), approval.get("user")
    )
    base_repo = base.get("repo") if isinstance(base, dict) else None
    if not (
        approval.get("merged") is True and approval.get("merged_at")
        and isinstance(base_repo, dict)
        and base.get("ref") == "main"
        and base_repo.get("full_name") == repository
        and isinstance(head, dict)
        and isinstance(head.get("sha"), str)
        and HEX40.fullmatch(head["sha"]) is not None
        and isinstance(author, dict)
        and isinstance(author.get("login"), str)
    ):
        return False
    files = _paged(
        f"https://api.github.com/repos/{repository}/pulls/{approval_pr}/files",
        token,
    )
    if (
        len(files) != 1
        or files[0].get("filename") != AUTHORITY_APPROVALS_PATH.as_posix()
        or files[0].get("status") not in {"added", "modified"}
    ):
        return False
    historical = _api_json(
        f"https://api.github.com/repos/{repository}/contents/"
        f"{AUTHORITY_APPROVALS_PATH.as_posix()}?ref={head['sha']}", token,
    )
    _require(
        isinstance(historical, dict)
        and historical.get("encoding") == "base64"
        and isinstance(historical.get("content"), str),
        "approved ledger's exact reviewed source unavailable",
    )
    try:
        snapshot = tomllib.loads(
            base64.b64decode(
                historical["content"].replace("\n", ""), validate=True,
            ).decode("utf-8")
        )
    except (ValueError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise QualificationError("approved ledger review source invalid") from exc
    records = snapshot.get("approval", []) if isinstance(snapshot, dict) else []
    if not isinstance(records, list) or not any(
        isinstance(record, dict)
        and record.get("bundle_sha256") == bundle_digest
        and record.get("review_pr") == approval_pr
        and record.get("approval_mode") == approval_mode
        for record in records
    ):
        return False

    if approval_mode == "solo-operator":
        if snapshot.get("solo_operator") != solo_operator:
            return False
        # A single developer can deliberately authorize a separate protected
        # ledger PR, but they cannot skip either PR's native qualification.
        # The configured account belongs to trusted default-branch policy.
        if (
            code_author != solo_operator
            or author["login"] != solo_operator
            or approval.get("author_association") not in {"OWNER", "MEMBER"}
        ):
            return False
        return _verify_ledger_native_checks(
            root=root, contract=contract or load_contract(root),
            repository=repository, approval_pr=approval_pr,
            approval=approval, token=token,
        )

    if approval_mode != "independent-review":
        return False
    reviews = _paged(
        f"https://api.github.com/repos/{repository}/pulls/{approval_pr}/reviews",
        token,
    )
    latest: dict[str, dict[str, Any]] = {}
    for item in reviews:
        reviewer = item.get("user") if isinstance(item, dict) else None
        if isinstance(reviewer, dict) and isinstance(reviewer.get("login"), str):
            latest[reviewer["login"]] = item
    return any(
        reviewer not in (author["login"], code_author)
        and review.get("state") == "APPROVED"
        and review.get("commit_id") == head["sha"]
        and review.get("author_association") in {"OWNER", "MEMBER", "COLLABORATOR"}
        for reviewer, review in latest.items()
    )


def evaluate_pr(
    *,
    root: Path,
    repository: str,
    pr_number: int,
    head_sha: str,
    token: str,
    validated_contract: dict[str, Any] | None = None,
    head_runs_snapshot: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _require(
        HEX40.fullmatch(head_sha) is not None,
        "head SHA must be an exact 40-hex commit",
    )
    contract = validated_contract if validated_contract is not None else load_contract(root)
    if validated_contract is None:
        validate_repository(root, contract)
    _require(
        repository == contract["repository"],
        "repository argument does not match matrix",
    )

    pr = _api_json(
        f"https://api.github.com/repos/{repository}/pulls/{pr_number}",
        token,
    )
    _require(isinstance(pr, dict), "invalid PR response")
    actual_head = (
        ((pr.get("head") or {}).get("sha"))
        if isinstance(pr.get("head"), dict)
        else None
    )
    _require(
        actual_head == head_sha,
        f"PR head moved: expected {head_sha}, current {actual_head}",
    )

    declared_count = pr.get("changed_files")
    _require(
        type(declared_count) is int and declared_count >= 0,
        "GitHub PR changed-file count unavailable or malformed",
    )
    if declared_count > 3000:
        # GitHub filters path-triggered workflows against no more than the
        # first 3,000 diff entries. Its PR-files API is capped at 3,000 too.
        # Do not infer missing workflows from a truncated, unsound diff.
        return {
            "schema_version": 1,
            "repository": repository,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "changed_paths": [],
            "required_gate_ids": list(contract["mandatory_gate_ids"]),
            "accepted": [],
            "waiting": [],
            "failures": [
                f"PR changes {declared_count} files; GitHub only filters/exposes "
                "the first 3,000, so qualification cannot be proven. Split the PR."
            ],
            "state": "failure",
            "status_context": contract["branch_required_check"],
        }

    changed_paths = _pr_changed_paths(repository, pr_number, token)
    _require(
        len(changed_paths) == declared_count
        and len(set(changed_paths)) == declared_count,
        f"GitHub PR file inventory incomplete or duplicated: expected "
        f"{declared_count} unique changed paths, received {len(changed_paths)}",
    )
    required_ids = required_gate_ids(contract, changed_paths)
    # Separate eligibility (GitHub uses rename destinations) from source
    # deletion safety (the source path is also affected). Never accept a
    # rename that requires a specialized gate which GitHub did not trigger.
    original_paths = _pr_changed_paths(
        repository, pr_number, token, include_rename_sources=True,
    )
    _require(
        set(changed_paths).issubset(original_paths),
        "rename-aware inventory does not cover changed PR paths",
    )
    unrouted_renames = sorted(
        set(required_gate_ids(contract, original_paths)) - set(required_ids)
    )
    if unrouted_renames:
        return {
            "schema_version": 1,
            "repository": repository,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "changed_paths": changed_paths,
            "required_gate_ids": required_ids,
            "accepted": [],
            "waiting": [],
            "failures": [
                "Rename removes protected source paths without starting "
                "their applicable native PR workflows: "
                + ", ".join(unrouted_renames)
                + ". Split into independently qualified deletion and addition."
            ],
            "state": "failure",
            "status_context": contract["branch_required_check"],
        }
    # Trust-boundary enforcement runs from default-branch source. No success
    # returned by a PR-edited gate workflow, local action, or its authority
    # validator can establish that the reviewed implementation executed.
    # Rename sources are affected authority even if GitHub routes only the
    # destination. Removing a native-only gate checker must not escape review.
    tampering = _untrusted_gate_definition_edits(
        contract, original_paths, root=root,
    )
    approvals = _approved_gate_bundles(root)
    independent_approval = False
    if tampering and approvals:
        bundle_digest = _authority_bundle_digest(
            repository, pr_number, token, tampering, pr=pr,
        )
        approval = approvals.get(bundle_digest)
        if approval is not None:
            owner = pr.get("user")
            code_author = owner.get("login") if isinstance(owner, dict) else None
            if isinstance(code_author, str) and code_author:
                approval_pr, approval_mode = approval
                policy = _load_toml(root, AUTHORITY_APPROVALS_PATH)
                independent_approval = _independently_reviewed_authority_upgrade(
                    repository, approval_pr, pr_number, bundle_digest, token,
                    code_author=code_author,
                    approval_mode=approval_mode,
                    solo_operator=policy["solo_operator"],
                    root=root, contract=contract,
                )
    if tampering and not independent_approval:
        return {
            "schema_version": 1,
            "repository": repository,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "changed_paths": changed_paths,
            "required_gate_ids": required_ids,
            "accepted": [],
            "waiting": [],
            "failures": [
                "PR changes executable qualification authority: "
                + ", ".join(tampering[:8])
                + "; native PR check names alone cannot establish trusted "
                "workflow execution. A separate protected-main approval "
                "PR must authorize the exact authority bundle digest; "
                "independent review or solo-operator native proof is "
                "required; no same-PR self-authorization."
            ],
            "state": "failure",
            "status_context": contract["branch_required_check"],
        }
    gates = _gates_by_id(contract)
    merge_sha = _reviewed_test_merge(repository, pr, head_sha, token)
    runs = head_runs_snapshot if head_runs_snapshot is not None else _head_runs(repository, head_sha, token)
    pr_base = _pr_base_identity(pr)
    waiting: list[str] = []
    failures: list[str] = []
    accepted: list[dict[str, Any]] = []

    for gate_id in required_ids:
        gate = gates[gate_id]
        run = _newest_matching_run(
            runs,
            gate=gate,
            head_sha=head_sha,
            pr_number=pr_number,
            pr_base=pr_base, merge_sha=merge_sha,
        )
        if run is None:
            if _has_stale_pr_base_run(
                runs, gate=gate, head_sha=head_sha,
                pr_number=pr_number, pr_base=pr_base, merge_sha=merge_sha,
            ):
                # No automatic native PR workflow runs are started when
                # main advances. In particular, rerunning old Actions
                # attempts or accepting workflow_dispatch is not fresh
                # evidence of the new base. Require a real PR event.
                failures.append(
                    f"{gate_id}: PR base changed; refresh PR head against "
                    "current base or reopen PR to trigger new native checks"
                )
            else:
                waiting.append(f"{gate_id}: absent")
            continue
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status != "completed":
            waiting.append(f"{gate_id}: {status or 'unknown'}")
            continue
        if conclusion not in SUPPORTED_CONCLUSIONS:
            failures.append(
                f"{gate_id}: unknown completed conclusion {conclusion!r}"
            )
            continue
        if conclusion != "success":
            failures.append(
                f"{gate_id}: exact-head PR run concluded {conclusion}"
            )
            continue
        try:
            job_paths = changed_paths
            if gate_id == "v09-qualification":
                # Workflow scope runs git diff --no-renames: both sides of a
                # rename affect the full-versus-regression job decision.
                # Keep general workflow applicability destination-only.
                job_paths = _pr_changed_paths(
                    repository, pr_number, token,
                    include_rename_sources=True,
                )
                _require(
                    set(changed_paths).issubset(set(job_paths)),
                    "v0.9 rename-aware inventory does not cover routed PR files",
                )
            job_mode = _verify_required_jobs(
                repository,
                gate,
                run,
                token,
                root=root,
                changed_paths=job_paths,
            )
        except QualificationError as exc:
            failures.append(str(exc))
            continue
        accepted.append(
            {
                "gate_id": gate_id,
                "workflow": gate["workflow"],
                "run_id": int(run["id"]),
                "run_attempt": int(run.get("run_attempt") or 1),
                "conclusion": "success",
                "job_mode": job_mode,
            }
        )

    state = "failure" if failures else ("pending" if waiting else "success")
    return {
        "schema_version": 1,
        "repository": repository,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "changed_paths": changed_paths,
        "required_gate_ids": required_ids,
        "accepted": accepted,
        "waiting": waiting,
        "failures": failures,
        "state": state,
        "status_context": contract["branch_required_check"],
    }


def _status_description(result: dict[str, Any]) -> str:
    state = result["state"]
    if state == "success":
        value = (
            f"{len(result['required_gate_ids'])} applicable exact-head gates passed"
        )
    elif state == "failure":
        value = "Failed: " + "; ".join(result["failures"][:2])
    else:
        value = "Waiting: " + "; ".join(result["waiting"][:3])
    return value[:140]


def reconcile_pr(
    *,
    root: Path,
    repository: str,
    pr_number: int,
    head_sha: str,
    token: str,
) -> dict[str, Any]:
    """Compatibility entrypoint; authorization is head-wide, not PR-local.

    Reconcile directly rather than fetching PR metadata before revoking
    an existing success. Even stale PR events must refresh any other PRs
    that continue to share the event's contributor head commit.
    """
    _require(isinstance(pr_number, int) and pr_number > 0, "invalid PR number")
    return reconcile_head(
        root=root, repository=repository, head_sha=head_sha, token=token
    )


def verify_pr(
    *,
    root: Path,
    repository: str,
    pr_number: int,
    head_sha: str,
    token: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        result = evaluate_pr(
            root=root,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            token=token,
        )
        if result["state"] == "success":
            return result
        if result["state"] == "failure":
            raise QualificationError(
                "applicable exact-head PR gates failed: "
                + "; ".join(result["failures"])
            )
        if time.monotonic() >= deadline:
            raise QualificationError(
                "timed out waiting for applicable exact-head PR gates: "
                + ", ".join(result["waiting"])
            )
        print(
            "waiting for exact-head qualification: "
            + ", ".join(result["waiting"]),
            file=sys.stderr,
            flush=True,
        )
        time.sleep(poll_seconds)

def _open_head_prs(
    repository: str, head_sha: str, token: str
) -> dict[int, tuple[str, str, int, str, int, str]]:
    """Resolve every open PR sharing a SHA; record a stable head/base identity."""
    associations = _paged(
        f"https://api.github.com/repos/{repository}/commits/{head_sha}/pulls",
        token,
    )
    selected: dict[int, tuple[str, str, int, str, int, str]] = {}
    for item in associations:
        _require(isinstance(item, dict), "invalid associated PR")
        if item.get("state") != "open":
            continue
        number = item.get("number")
        _require(
            isinstance(number, int) and number > 0 and number not in selected,
            "invalid/duplicate PR association for commit",
        )
        pr = _api_json(
            f"https://api.github.com/repos/{repository}/pulls/{number}", token
        )
        _require(isinstance(pr, dict), "invalid live PR")
        if pr.get("state") != "open":
            continue
        pr_head = pr.get("head")
        _require(isinstance(pr_head, dict), "PR head metadata missing")
        if pr_head.get("sha") != head_sha:
            continue
        source_repo = pr_head.get("repo")
        _require(isinstance(source_repo, dict), "PR source repository missing")
        branch, repo_id = pr_head.get("ref"), source_repo.get("id")
        _require(
            isinstance(branch, str) and bool(branch)
            and isinstance(repo_id, int) and repo_id > 0,
            "PR source identity incomplete",
        )
        base = _pr_base_identity(pr)
        merge = pr.get("merge_commit_sha")
        _require(
            isinstance(merge, str) and HEX40.fullmatch(merge) is not None,
            "PR synthetic merge SHA unavailable",
        )
        selected[number] = (*base, branch, repo_id, merge)
    return dict(sorted(selected.items()))


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    _require(bool(results), "cannot authorize an unassociated commit")
    problems = [
        f"#{item['pr_number']}: {problem}"
        for item in results
        for problem in item["failures"]
    ]
    waiting = [
        f"#{item['pr_number']}: {problem}"
        for item in results
        for problem in item["waiting"]
    ]
    state = "failure" if problems else ("pending" if waiting else "success")
    return {
        "state": state,
        "failures": problems,
        "waiting": waiting,
        "pr_count": len(results),
        "results": results,
    }


def reconcile_head(
    *,
    root: Path,
    repository: str,
    head_sha: str,
    token: str,
) -> dict[str, Any]:
    """One head-SHA writer; all open PRs sharing the SHA must qualify."""
    _require(HEX40.fullmatch(head_sha) is not None, "invalid head SHA")
    contract = load_contract(root)
    _require(repository == contract["repository"], "repository mismatch")
    status_url = f"https://api.github.com/repos/{repository}/statuses/{head_sha}"
    status_context = contract["branch_required_check"]
    target = f"https://github.com/{repository}/commit/{head_sha}"
    # Revoke stale success *before* fallible PR association and identity lookups.
    # A newly opened shared-head PR can temporarily have no test-merge SHA.
    # Those incomplete responses must never leave the previous success usable.
    # All event sources share the same head-SHA concurrency key.
    pending_status = {
        "state": "pending",
        "context": status_context,
        "description": "Rechecking every open PR for this source commit",
        "target_url": target,
    }
    _post_json(status_url, token, pending_status)
    identities = _open_head_prs(repository, head_sha, token)
    if not identities:
        return {
            "schema_version": 1,
            "repository": repository,
            "head_sha": head_sha,
            "pr_count": 0,
            "state": "ignored-no-open-pr",
            "status_sha": head_sha,
            "published_status": pending_status,
        }

    # A shared head can have arbitrarily many PR associations; limiting
    # one head per writer does not bound the expensive REST work within it.
    # Refuse oversized shared-head sets rather than silently consuming the
    # entire repository token budget or timing out after stale invalidation.
    if len(identities) > 8:
        description = (
            f"Failed: {len(identities)} PRs share this head; "
            "maximum supported is 8. Split shared-head PRs."
        )
        status = {
            "state": "failure",
            "context": status_context,
            "description": description[:140],
            "target_url": target,
        }
        _post_json(status_url, token, status)
        return {
            "schema_version": 1,
            "repository": repository,
            "head_sha": head_sha,
            "pr_count": len(identities),
            "state": "failure",
            "failures": [description],
            "waiting": [],
            "status_sha": head_sha,
            "published_status": status,
        }

    def inspect() -> dict[str, Any]:
        return _aggregate([
            evaluate_pr(
                root=root,
                repository=repository,
                pr_number=number,
                head_sha=head_sha,
                token=token,
            )
            for number in identities
        ])

    result = inspect()
    # Gate reruns can begin while earlier results are read. Never publish
    # success based solely on a previous snapshot.
    if result["state"] == "success":
        result = inspect()
    latest = _open_head_prs(repository, head_sha, token)
    if latest != identities or (
        result["state"] == "success"
        and _open_head_prs(repository, head_sha, token) != identities
    ):
        return {
            **result,
            "schema_version": 1,
            "repository": repository,
            "head_sha": head_sha,
            "state": "ignored-stale-pr-identity",
            "published_status": None,
        }
    if result["state"] == "success":
        description = f"{result['pr_count']} PR(s): all applicable gates passed"
    elif result["state"] == "failure":
        description = "Failed: " + "; ".join(result["failures"][:2])
    else:
        description = "Waiting: " + "; ".join(result["waiting"][:2])
    status = {
        "state": result["state"],
        "context": status_context,
        "description": description[:140],
        "target_url": target,
    }
    _post_json(status_url, token, status)
    return {
        **result,
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "status_sha": head_sha,
        "published_status": status,
    }



def decision_head(
    *,
    root: Path,
    repository: str,
    head_sha: str,
    token: str,
) -> dict[str, Any]:
    """Read-only independent App receipt for every live main-targeting PR.

    No GitHub status/check publication occurs in this function. The GitHub App
    separately authenticates the service, revokes old approvals, verifies PR
    test-merge parents, and owns the only required qualification check.
    """
    _require(HEX40.fullmatch(head_sha) is not None, "invalid decision head SHA")
    contract = load_contract(root)
    _require(repository == contract["repository"], "decision repository mismatch")
    validate_repository(root, contract)
    first = _open_head_prs(repository, head_sha, token)
    selected = {
        number: identity for number, identity in first.items()
        if identity[0] == "main"
    }
    _require(bool(selected), "head has no open main-targeting PR")
    _require(len(selected) <= 8, "shared decision head exceeds eight PRs")

    def evaluate_all() -> list[dict[str, Any]]:
        # Cache expensive PR-file and immutable run-attempt job inventories
        # only within a single snapshot. Positive results repeat with new
        # live GitHub reads, never with reused authorization evidence.
        file_token = _PR_FILE_BATCH.set({})
        job_token = _RUN_JOBS_BATCH.set({})
        try:
            runs = _head_runs(repository, head_sha, token)
            return [
                evaluate_pr(
                    root=root, repository=repository, pr_number=number,
                    head_sha=head_sha, token=token,
                    validated_contract=contract, head_runs_snapshot=runs,
                )
                for number in selected
            ]
        finally:
            _RUN_JOBS_BATCH.reset(job_token)
            _PR_FILE_BATCH.reset(file_token)

    results = evaluate_all()
    if all(item.get("state") == "success" for item in results):
        # Prevent a prior green workflow-run snapshot from authorizing a rerun
        # that has begun while the first PR batch was being inspected.
        results = evaluate_all()

    fresh = _open_head_prs(repository, head_sha, token)
    _require(
        {number: identity for number, identity in fresh.items()
         if identity[0] == "main"} == selected,
        "PR identity changed during independent decision",
    )

    prs = []
    states = []
    for number, result in zip(selected, results, strict=True):
        _require(
            isinstance(result, dict)
            and result.get("schema_version") == 1
            and result.get("repository") == repository
            and result.get("pr_number") == number
            and result.get("head_sha") == head_sha
            and result.get("state") in ("success", "pending", "failure"),
            "malformed per-PR independent decision",
        )
        required = result.get("required_gate_ids")
        accepted_records = result.get("accepted")
        _require(
            isinstance(required, list) and bool(required)
            and all(isinstance(gate, str) for gate in required)
            and len(set(required)) == len(required)
            and set(contract["mandatory_gate_ids"]).issubset(required)
            and isinstance(accepted_records, list)
            and all(isinstance(entry, dict) and
                    isinstance(entry.get("gate_id"), str)
                    for entry in accepted_records),
            "invalid independent gate receipt",
        )
        accepted = [entry["gate_id"] for entry in accepted_records]
        _require(
            len(set(accepted)) == len(accepted)
            and set(accepted).issubset(required)
            and (result["state"] != "success" or set(accepted) == set(required)),
            "incomplete or ambiguous accepted gate receipt",
        )
        base_ref, base_sha, _, _, _, _ = selected[number]
        prs.append({
            "number": number,
            "head_sha": head_sha,
            "base_ref": base_ref,
            "base_sha": base_sha,
            "required_gate_ids": required,
            "accepted_gate_ids": accepted,
        })
        states.append(result["state"])
    state = "failure" if "failure" in states else (
        "pending" if "pending" in states else "success"
    )
    return {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "state": state,
        "prs": prs,
    }


def resolve_event_heads(
    *,
    repository: str,
    event_name: str,
    event: dict[str, Any],
    token: str,
) -> list[str]:
    """Find affected contributor commits without using PR-controlled code.

    Only pushes to protected main are trusted as base-update triggers.
    The workflow deliberately does not run on arbitrary contributor pushes.
    """
    _require(repository == "linura-org/linura", "unexpected repository")
    _require(isinstance(event, dict), "invalid GitHub event payload")
    heads: set[str] = set()
    if event_name == "pull_request_target":
        pr = event.get("pull_request")
        _require(isinstance(pr, dict), "PR event lacks pull request")
        source = pr.get("head")
        _require(isinstance(source, dict), "PR head missing")
        sha = source.get("sha")
        _require(isinstance(sha, str) and HEX40.fullmatch(sha) is not None,
                 "PR event missing exact head SHA")
        heads.add(sha)
        if event.get("action") == "synchronize":
            before = event.get("before")
            after = event.get("after")
            _require(
                isinstance(before, str) and HEX40.fullmatch(before) is not None,
                "synchronize event lacks valid previous head SHA",
            )
            _require(
                isinstance(after, str) and after == sha,
                "synchronize after SHA must match PR head",
            )
            heads.add(before)
    elif event_name == "workflow_run":
        run = event.get("workflow_run")
        _require(isinstance(run, dict), "missing workflow-run metadata")
        if run.get("event") == "pull_request":
            sha = run.get("head_sha")
            _require(isinstance(sha, str) and HEX40.fullmatch(sha) is not None,
                     "workflow run missing exact head SHA")
            heads.add(sha)
    elif event_name in ("push", "schedule"):
        if event_name == "push":
            _require(event.get("ref") == "refs/heads/main",
                     "base-update watcher must run only on protected main")
            _require(event.get("deleted") is not True, "deleted main branch")
        else:
            _require(event.get("schedule") == "17 * * * *",
                     "unknown qualification retry schedule")
        candidates = _paged(
            f"https://api.github.com/repos/{repository}/pulls?"
            + urlencode({"state": "open", "base": "main"}),
            token,
        )
        for pr in candidates:
            _require(isinstance(pr, dict), "invalid PR listing entry")
            if pr.get("state") != "open":
                continue
            base = pr.get("base")
            base_repo = base.get("repo") if isinstance(base, dict) else None
            _require(
                isinstance(base_repo, dict)
                and base.get("ref") == "main"
                and base_repo.get("full_name") == repository,
                "base-push discovered PR outside protected main",
            )
            source = pr.get("head")
            _require(isinstance(source, dict), "PR source missing on base push")
            sha = source.get("sha")
            _require(isinstance(sha, str) and HEX40.fullmatch(sha) is not None,
                     "PR source commit invalid on base push")
            heads.add(sha)
    else:
        raise QualificationError(f"unsupported summary event: {event_name}")
    return sorted(heads)



def group_head_shas(heads: list[str]) -> list[dict[str, Any]]:
    """Map any sized head set into at most 16 deterministic writer shards.

    GitHub permits at most 256 matrix jobs per run. The leading hex digit of
    a validated exact head is stable over time and uniform across event kinds,
    so all writers for a given head use one shared concurrency group.
    """
    buckets: dict[str, list[str]] = {}
    for head in sorted(set(heads)):
        _require(
            isinstance(head, str) and HEX40.fullmatch(head) is not None,
            "cannot group malformed head SHA",
        )
        buckets.setdefault(head[0], []).append(head)
    return [
        {"shard": shard, "heads": bucket}
        for shard, bucket in sorted(buckets.items())
    ]


def reconcile_heads(
    *,
    root: Path,
    repository: str,
    head_shas: list[str],
    shard: str,
    token: str,
    retry_only: bool = False,
    invalidate_only: bool = False,
    hour_slot: int | None = None,
) -> dict[str, Any]:
    """Invalidate all event heads, then bound costly per-head REST reads.

    Continue after individual GitHub failures: one unavailable head must
    not prevent later heads in the same shard from losing stale success.
    """
    _require(re.fullmatch(r"[0-9a-f]", shard) is not None, "invalid writer shard")
    _require(bool(head_shas), "empty reconciliation head shard")
    groups = group_head_shas(head_shas)
    _require(
        len(groups) == 1 and groups[0]["shard"] == shard
        and len(groups[0]["heads"]) == len(head_shas),
        "reconciliation heads must be unique and match writer shard",
    )
    contract = load_contract(root)
    _require(repository == contract["repository"], "repository mismatch")
    context = contract["branch_required_check"]
    ready: list[str] = []
    failures: list[str] = []
    _require(isinstance(retry_only, bool), "invalid retry mode")
    _require(isinstance(invalidate_only, bool), "invalid invalidate-only mode")
    _require(not (retry_only and invalidate_only), "retry and invalidate-only conflict")
    slot = int(time.time() // 3600) if hour_slot is None else hour_slot
    _require(isinstance(slot, int) and slot >= 0, "invalid retry hour")
    heads = groups[0]["heads"]
    # Maximum one expensive (20+ REST request) requalification per shard run.
    # Rotate hourly so stable backlogs drain without token-quota bursts.
    selected_head = heads[slot % len(heads)]
    invalidation_heads = [selected_head] if retry_only else heads
    for head in invalidation_heads:
        try:
            _post_json(
                f"https://api.github.com/repos/{repository}/statuses/{head}",
                token,
                {
                    "state": "pending",
                    "context": context,
                    "description": "Awaiting exact-head qualification reconciliation",
                    "target_url": f"https://github.com/{repository}/commit/{head}",
                },
            )
            ready.append(head)
        except Exception as exc:
            failures.append(f"{head}: could not invalidate stale status: {exc}")
    results: list[dict[str, Any]] = []
    for head in ([selected_head] if selected_head in ready and not invalidate_only else []):
        try:
            results.append(
                reconcile_head(
                    root=root, repository=repository, head_sha=head, token=token
                )
            )
        except Exception as exc:
            # The preliminary pending status remains in place for this head.
            failures.append(f"{head}: reconciliation failed: {exc}")
    return {
        "schema_version": 1,
        "repository": repository,
        "shard": shard,
        "head_count": len(head_shas),
        "invalidated_count": len(ready),
        "reconciled_count": len(results),
        "deferred_count": len(heads) - (0 if invalidate_only else 1),
        "retry_only": retry_only,
        "invalidate_only": invalidate_only,
        "selected_head": selected_head,
        "results": results,
        "failures": failures,
    }


def _command_event_heads(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(bool(token), "GitHub token environment is empty")
    event = json.loads(args.event_path.read_text(encoding="utf-8"))
    heads = resolve_event_heads(
        repository=args.repository,
        event_name=args.event_name,
        event=event,
        token=token,
    )
    groups = group_head_shas(heads)
    serialized = json.dumps(groups, separators=(",", ":"))
    with args.output.open("a", encoding="utf-8") as output:
        output.write(f"head_groups={serialized}\n")
    print(json.dumps({
        "event": args.event_name,
        "head_count": len(heads),
        "shard_count": len(groups),
    }))
    return 0



def _command_reconcile_heads(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(bool(token), "GitHub token environment is empty")
    heads = json.loads(args.heads_json)
    _require(
        isinstance(heads, list) and all(isinstance(v, str) for v in heads),
        "invalid head list",
    )
    result = reconcile_heads(
        root=args.root,
        repository=args.repository,
        head_shas=heads,
        shard=args.shard,
        token=token,
        retry_only=args.retry_only == "true",
        invalidate_only=args.invalidate_only == "true",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    _require(not result["failures"], "some head reconciliations failed")
    return 0


def _command_reconcile_head(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(bool(token), "GitHub token environment is empty")
    result = reconcile_head(
        root=args.root,
        repository=args.repository,
        head_sha=args.head_sha,
        token=token,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _command_reconcile_pr(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(
        token,
        "GitHub token environment variable is empty: "
        f"{args.token_env}",
    )
    result = reconcile_pr(
        root=args.root,
        repository=args.repository,
        pr_number=args.pr_number,
        head_sha=args.head_sha,
        token=token,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0



def _command_decision_head(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(bool(token), "GitHub read token is required")
    # Reserve five seconds for sanitized process teardown and App publication.
    deadline_token = _READ_DEADLINE.set(time.monotonic() + 115.0)
    try:
        receipt = decision_head(
            root=args.root, repository=args.repository,
            head_sha=args.head_sha, token=token,
        )
    finally:
        _READ_DEADLINE.reset(deadline_token)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


def _command_authority_bundle(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(bool(token), "GitHub token environment is empty")
    contract = load_contract(args.root)
    _require(args.repository == contract["repository"], "repository mismatch")
    paths = _pr_changed_paths(
        args.repository, args.pr_number, token,
        include_rename_sources=True,
    )
    tampering = _untrusted_gate_definition_edits(contract, paths, root=args.root)
    _require(bool(tampering), "PR has no changed executable gate authority")
    digest = _authority_bundle_digest(
        args.repository, args.pr_number, token, tampering,
    )
    print(json.dumps({
        "bundle_sha256": digest,
        "changed_authority_paths": tampering,
        "review_pr": args.pr_number,
        "note": "Requires a separate reviewed PR to the protected-main ledger",
    }, indent=2, sort_keys=True))
    return 0


def _command_validate(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            validate_repository(args.root), indent=2, sort_keys=True
        )
    )
    return 0


def _command_plan(args: argparse.Namespace) -> int:
    contract = load_contract(args.root)
    validate_repository(args.root, contract)
    paths = [
        line.strip()
        for line in args.paths_file.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    print(
        json.dumps(
            {
                "paths": paths,
                "required_gate_ids": required_gate_ids(contract, paths),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _command_verify_pr(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    _require(
        token,
        "GitHub token environment variable is empty: "
        f"{args.token_env}",
    )
    result = verify_pr(
        root=args.root,
        repository=args.repository,
        pr_number=args.pr_number,
        head_sha=args.head_sha,
        token=token,
        timeout_seconds=args.timeout_seconds,
        poll_seconds=args.poll_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.set_defaults(func=_command_validate)

    plan = sub.add_parser("plan")
    plan.add_argument("--paths-file", type=Path, required=True)
    plan.set_defaults(func=_command_plan)

    authority = sub.add_parser("authority-bundle")
    authority.add_argument("--repository", required=True)
    authority.add_argument("--pr-number", type=int, required=True)
    authority.add_argument("--token-env", default="GITHUB_TOKEN")
    authority.set_defaults(func=_command_authority_bundle)

    verify = sub.add_parser("verify-pr")
    verify.add_argument("--repository", required=True)
    verify.add_argument("--pr-number", type=int, required=True)
    verify.add_argument("--head-sha", required=True)
    verify.add_argument("--token-env", default="GITHUB_TOKEN")
    verify.add_argument("--timeout-seconds", type=int, default=7200)
    verify.add_argument("--poll-seconds", type=int, default=20)
    verify.set_defaults(func=_command_verify_pr)

    reconcile = sub.add_parser("reconcile-pr")
    reconcile.add_argument("--repository", required=True)
    reconcile.add_argument("--pr-number", type=int, required=True)
    reconcile.add_argument("--head-sha", required=True)
    reconcile.add_argument("--token-env", default="GITHUB_TOKEN")
    reconcile.set_defaults(func=_command_reconcile_pr)

    reconcile_head_parser = sub.add_parser("reconcile-head")
    reconcile_head_parser.add_argument("--repository", required=True)
    reconcile_head_parser.add_argument("--head-sha", required=True)
    reconcile_head_parser.add_argument("--token-env", default="GITHUB_TOKEN")
    reconcile_head_parser.set_defaults(func=_command_reconcile_head)

    decision_parser = sub.add_parser("decision-head")
    decision_parser.add_argument("--repository", required=True)
    decision_parser.add_argument("--head-sha", required=True)
    decision_parser.add_argument("--token-env", default="GITHUB_TOKEN")
    decision_parser.set_defaults(func=_command_decision_head)

    discover = sub.add_parser("event-heads")
    discover.add_argument("--repository", required=True)
    discover.add_argument("--event-name", required=True)
    discover.add_argument("--event-path", type=Path, required=True)
    discover.add_argument("--output", type=Path, required=True)
    discover.add_argument("--token-env", default="GITHUB_TOKEN")
    discover.set_defaults(func=_command_event_heads)

    reconcile_group = sub.add_parser("reconcile-heads")
    reconcile_group.add_argument("--repository", required=True)
    reconcile_group.add_argument("--heads-json", required=True)
    reconcile_group.add_argument("--shard", required=True)
    reconcile_group.add_argument("--retry-only", choices=("true", "false"), default="false")
    reconcile_group.add_argument("--invalidate-only", choices=("true", "false"), default="false")
    reconcile_group.add_argument("--token-env", default="GITHUB_TOKEN")
    reconcile_group.set_defaults(func=_command_reconcile_heads)

    args = parser.parse_args()
    try:
        return args.func(args)
    except QualificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
