#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import hashlib
import re
import sys
import tomllib

from check_v010_workstation_qualification import (
    validate as validate_v010_workstation_qualification,
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VALID_STATUS = {"released", "planned"}
VALID_CLAIM_CLASS = {"Experimental", "Preview", "Stable"}
VALID_EXECUTOR_STATE = {"none", "isolated-qualified", "integrated-narrow"}
VALID_MUTATION_SUPPORT = {"none", "narrow-experimental", "reference-experimental", "reference-stable"}
VALID_AGENT_ROLE = {"none", "proposal-only"}
VALID_PLATFORM_SUPPORT = {"none", "reference-experimental", "reference-stable"}
CANONICAL_LIFECYCLE = (
    "request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile"
)
V010_SLICE_CONTRACT = "contracts/v010-workstation-slices.toml"
V010_PRODUCT_SCOPE_ADR = "docs/adr/0033-v010-complete-workstation-product-boundary.md"
V010_QUALIFICATION_CONTRACT = "contracts/v010-workstation-qualification.toml"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
V010_SLICE_COUNT = 32
V010_COMPLETED_SLICE_COUNT = 14
V010_NEXT_SLICE = "S15"
V010_SLICE_TITLES = (
    "v0.10 workstation contract and qualification foundation",
    "typed arch-hyprland-v1 PlatformProfile compatibility",
    "native platform discovery and bounded probes",
    "multi-interface and operation-semantics contracts",
    "trusted operation registry and Control resolution",
    "managed-effect reference operation",
    "bounded transient-effect Control path",
    "PipeWire/WirePlumber session-volume authority slice",
    "unified Linura Shell and Control Center host",
    "Linura QML UI SDK and design-system foundation",
    "bounded command palette",
    "typed workspace navigation and application launcher",
    "authoritative Quick Settings",
    "exact-source shell runtime qualification and immutable Arch substrate",
    "lifecycle notifications and OSD",
    "first-party panel, tray, status and workstation entry points",
    "lock screen and session/power controls",
    "NetworkManager connectivity experience",
    "BlueZ Bluetooth experience",
    "complete audio and media experience",
    "display, brightness, power and removable-storage experience",
    "desktop utilities, screenshot/recording and clipboard history",
    "applications, packages and default-app management",
    "updates, snapshots, rollback and recovery experience",
    "themes, wallpaper, fonts, icons and personalization",
    "Library, Setups and MachineProfiles workstation workflows",
    "declarative configuration, manual/no-AI and agent convergence",
    "bounded installer and First Boot workstation path",
    "Q10 complete experience, visual, accessibility and input qualification",
    "Q11 maintained real Arch/Hyprland hardware qualification",
    "Q12/Q13 recovery, power-loss and workstation security qualification",
    "Q14/Q15 inherited qualification, support promotion and release closure",
)


def version_key(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid semantic milestone version: {value!r}")
    return tuple(int(part) for part in match.groups())



def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_v010_release_artifact(
    root: Path,
    relative_path: object,
    expected_digest: object,
    label: str,
    failures: list[str],
) -> None:
    if not isinstance(relative_path, str) or not relative_path:
        failures.append(f"released v0.10 requires {label} path")
        return
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        failures.append(f"released v0.10 {label} path must remain repository-relative")
        return
    if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
        failures.append(f"released v0.10 requires SHA-256 binding for {label}")
        return
    artifact = root / candidate
    if not artifact.is_file() or artifact.is_symlink():
        failures.append(f"released v0.10 qualification artifact missing or unsafe: {relative_path}")
        return
    if _sha256(artifact) != expected_digest:
        failures.append(f"released v0.10 qualification artifact digest mismatch: {relative_path}")


def validate_v010_release_readiness(root: Path) -> list[str]:
    failures: list[str] = []
    path = root / V010_QUALIFICATION_CONTRACT
    if not path.is_file():
        return [f"released v0.10 requires {V010_QUALIFICATION_CONTRACT}"]
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        return [f"invalid {V010_QUALIFICATION_CONTRACT}: {error}"]

    if contract.get("milestone") != "v0.10.0":
        failures.append("released v0.10 qualification contract must bind milestone v0.10.0")

    substrate = contract.get("substrate")
    if not isinstance(substrate, dict):
        failures.append("released v0.10 requires substrate qualification readiness")
    else:
        if substrate.get("state") != "frozen":
            failures.append("released v0.10 requires frozen immutable Arch substrate")
        if substrate.get("release_qualification_ready") is not True:
            failures.append("released v0.10 requires substrate.release_qualification_ready=true")
        _validate_v010_release_artifact(
            root,
            substrate.get("package_manifest"),
            substrate.get("package_manifest_sha256"),
            "package manifest",
            failures,
        )

    experience = contract.get("experience")
    if not isinstance(experience, dict):
        failures.append("released v0.10 requires experience qualification readiness")
    else:
        if experience.get("experience_evidence_ready") is not True:
            failures.append("released v0.10 requires experience.experience_evidence_ready=true")
        _validate_v010_release_artifact(
            root,
            experience.get("visual_baseline_manifest"),
            experience.get("visual_baseline_manifest_sha256"),
            "visual baseline manifest",
            failures,
        )
        _validate_v010_release_artifact(
            root,
            experience.get("experience_evidence_manifest"),
            experience.get("experience_evidence_manifest_sha256"),
            "experience evidence manifest",
            failures,
        )

    return failures


def _v010_release_gate_required(
    root: Path,
    milestone_status: object,
    next_release: object,
) -> bool:
    if milestone_status == "released":
        return True
    if milestone_status != "planned" or next_release != "v0.10.0":
        return False
    path = root / V010_SLICE_CONTRACT
    if not path.is_file() or path.is_symlink():
        return False
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    slices = contract.get("slice")
    return (
        isinstance(slices, list)
        and len(slices) == V010_SLICE_COUNT
        and all(
            isinstance(item, dict)
            and item.get("required_for_release") is True
            and item.get("status") == "complete"
            for item in slices
        )
    )


def validate_v010_slice_contract(root: Path, milestone_status: object) -> list[str]:
    failures: list[str] = []
    path = root / V010_SLICE_CONTRACT
    if not path.is_file():
        return [f"missing {V010_SLICE_CONTRACT}"]
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        return [f"invalid {V010_SLICE_CONTRACT}: {error}"]

    if contract.get("schema_version") != 1:
        failures.append("v0.10 slice contract schema_version must remain 1")
    if contract.get("milestone") != "v0.10.0":
        failures.append("v0.10 slice contract milestone must remain v0.10.0")
    if contract.get("target") != "complete-experimental-workstation":
        failures.append("v0.10 slice contract target must remain complete-experimental-workstation")
    if contract.get("completion_policy") != "contiguous-prefix-with-merged-pr-evidence":
        failures.append("v0.10 slice completion policy drifted")
    if contract.get("scope_change_policy") != "explicit-roadmap-rebaseline":
        failures.append("v0.10 slice scope changes must require explicit roadmap rebaseline")

    slices = contract.get("slice")
    if not isinstance(slices, list):
        return failures + ["v0.10 slice contract must define [[slice]] entries"]
    if len(slices) != V010_SLICE_COUNT or contract.get("slice_count") != V010_SLICE_COUNT:
        failures.append(f"v0.10 slice contract must remain exactly {V010_SLICE_COUNT} slices")

    expected_ids = [f"S{index:02d}" for index in range(1, V010_SLICE_COUNT + 1)]
    actual_ids: list[str] = []
    completed = 0
    seen_planned = False
    for index, item in enumerate(slices):
        if not isinstance(item, dict):
            failures.append(f"v0.10 slice #{index + 1} must be a table")
            continue
        slice_id = item.get("id")
        actual_ids.append(slice_id if isinstance(slice_id, str) else "")
        title = item.get("title")
        status = item.get("status")
        dependencies = item.get("depends_on")
        evidence = item.get("evidence_prs")
        expected_title = V010_SLICE_TITLES[index] if index < len(V010_SLICE_TITLES) else None
        if title != expected_title:
            failures.append(
                f"{slice_id or index + 1}: slice title/scope drifted; "
                f"expected {expected_title!r}, found {title!r}"
            )
        if status not in {"complete", "planned"}:
            failures.append(f"{slice_id or index + 1}: slice status must be complete or planned")
        if item.get("required_for_release") is not True:
            failures.append(f"{slice_id or index + 1}: every v0.10 slice must remain required_for_release")
        expected_dep = [] if index == 0 else [expected_ids[index - 1]]
        if dependencies != expected_dep:
            failures.append(f"{slice_id or index + 1}: slice dependency must preserve sequential ledger order")
        if not isinstance(evidence, list) or not all(
            type(value) is int and value > 0 for value in evidence
        ):
            failures.append(f"{slice_id or index + 1}: evidence_prs must be positive PR numbers")
            evidence = []
        if status == "complete":
            if seen_planned:
                failures.append("v0.10 completed slices must remain a contiguous prefix")
            completed += 1
            if not evidence:
                failures.append(f"{slice_id or index + 1}: completed slice requires merged-PR evidence")
        elif status == "planned":
            seen_planned = True
            if evidence:
                failures.append(f"{slice_id or index + 1}: planned slice must not carry completion evidence")

    if actual_ids != expected_ids:
        failures.append("v0.10 slice IDs/order drifted from S01..S32")
    if contract.get("completed_slice_count") != completed:
        failures.append("v0.10 completed_slice_count does not match slice statuses")

    if milestone_status == "released":
        incomplete_release_slices = [
            item.get("id")
            for item in slices
            if isinstance(item, dict)
            and item.get("required_for_release") is True
            and item.get("status") != "complete"
        ]
        if incomplete_release_slices:
            failures.append(
                "released v0.10 requires all release-required slices complete: "
                + ", ".join(
                    value for value in incomplete_release_slices if isinstance(value, str)
                )
            )
        if completed != V010_SLICE_COUNT:
            failures.append(
                f"released v0.10 must have all {V010_SLICE_COUNT} workstation slices complete"
            )
        if contract.get("next_slice") not in {None, ""}:
            failures.append("released v0.10 must not retain a next_slice")
    else:
        if completed != V010_COMPLETED_SLICE_COUNT:
            failures.append(
                f"v0.10 completed slice count must remain {V010_COMPLETED_SLICE_COUNT} until the ledger advances atomically"
            )
        if contract.get("next_slice") != V010_NEXT_SLICE:
            failures.append(f"v0.10 next_slice must remain {V010_NEXT_SLICE} until S15 completes")
        if completed < len(slices):
            next_item = slices[completed]
            next_id = next_item.get("id") if isinstance(next_item, dict) else None
            if next_id != contract.get("next_slice"):
                failures.append("v0.10 next_slice must identify the first planned slice")
    return failures


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract_path = root / "contracts/roadmap.toml"
    if not contract_path.is_file():
        return ["missing contracts/roadmap.toml"]

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as error:
        return [f"invalid contracts/roadmap.toml: {error}"]

    if contract.get("schema_version") != 1:
        failures.append("roadmap schema_version must be 1")
    if contract.get("product_stability") != "experimental":
        failures.append(
            "roadmap product_stability must describe the current product as experimental until a future explicit Stable release transition"
        )
    if contract.get("canonical_lifecycle") != CANONICAL_LIFECYCLE:
        failures.append(
            "roadmap canonical_lifecycle changed; the locked eleven-stage lifecycle requires an explicit architecture rebaseline"
        )

    milestones = contract.get("milestone")
    if not isinstance(milestones, list) or not milestones:
        return failures + ["roadmap contract must define at least one [[milestone]]"]

    required_fields = {
        "version",
        "title",
        "status",
        "claim_class",
        "depends_on",
        "durable_recovery",
        "executor_state",
        "complete_lifecycle",
        "managed_mutation_support",
        "agent_role",
        "platform_support",
    }

    by_version: dict[str, dict[str, object]] = {}
    ordered_versions: list[str] = []
    seen_planned = False

    for index, milestone in enumerate(milestones):
        if not isinstance(milestone, dict):
            failures.append(f"milestone #{index + 1} must be a table")
            continue

        missing = sorted(required_fields - milestone.keys())
        if missing:
            failures.append(f"milestone #{index + 1} missing fields: {missing}")
            continue

        version = milestone.get("version")
        title = milestone.get("title")
        status = milestone.get("status")
        claim_class = milestone.get("claim_class")
        depends_on = milestone.get("depends_on")
        durable_recovery = milestone.get("durable_recovery")
        executor_state = milestone.get("executor_state")
        complete_lifecycle = milestone.get("complete_lifecycle")
        mutation_support = milestone.get("managed_mutation_support")
        agent_role = milestone.get("agent_role")
        platform = milestone.get("platform_support")

        if not isinstance(version, str):
            failures.append(f"milestone #{index + 1} version must be a string")
            continue
        try:
            version_key(version)
        except ValueError as error:
            failures.append(str(error))
            continue
        if version in by_version:
            failures.append(f"duplicate roadmap milestone: {version}")
            continue
        if not isinstance(title, str) or not title.strip():
            failures.append(f"{version}: title must be a non-empty string")
        if status not in VALID_STATUS:
            failures.append(f"{version}: unsupported status {status!r}")
        if claim_class not in VALID_CLAIM_CLASS:
            failures.append(f"{version}: unsupported claim_class {claim_class!r}")
        if not isinstance(depends_on, list) or not all(isinstance(item, str) for item in depends_on):
            failures.append(f"{version}: depends_on must be an array of milestone versions")
        if not isinstance(durable_recovery, bool):
            failures.append(f"{version}: durable_recovery must be boolean")
        if executor_state not in VALID_EXECUTOR_STATE:
            failures.append(f"{version}: unsupported executor_state {executor_state!r}")
        if not isinstance(complete_lifecycle, bool):
            failures.append(f"{version}: complete_lifecycle must be boolean")
        if mutation_support not in VALID_MUTATION_SUPPORT:
            failures.append(f"{version}: unsupported managed_mutation_support {mutation_support!r}")
        if agent_role not in VALID_AGENT_ROLE:
            failures.append(f"{version}: unsupported agent_role {agent_role!r}")
        if platform not in VALID_PLATFORM_SUPPORT:
            failures.append(f"{version}: unsupported platform_support {platform!r}")

        if status == "planned":
            seen_planned = True
        elif status == "released" and seen_planned:
            failures.append(f"{version}: released milestones must form a contiguous prefix")

        by_version[version] = milestone
        ordered_versions.append(version)

    try:
        ordered_keys = [version_key(version) for version in ordered_versions]
        if ordered_keys != sorted(ordered_keys) or len(set(ordered_keys)) != len(ordered_keys):
            failures.append("roadmap milestones must be strictly increasing by semantic version")
    except ValueError:
        pass

    for version, milestone in by_version.items():
        depends_on = milestone.get("depends_on")
        if not isinstance(depends_on, list):
            continue
        for dependency in depends_on:
            if dependency not in by_version:
                failures.append(f"{version}: unknown dependency {dependency}")
                continue
            try:
                if version_key(dependency) >= version_key(version):
                    failures.append(f"{version}: dependency {dependency} must precede the milestone")
            except ValueError:
                continue

    released = [
        version
        for version in ordered_versions
        if by_version.get(version, {}).get("status") == "released"
    ]
    planned = [
        version
        for version in ordered_versions
        if by_version.get(version, {}).get("status") == "planned"
    ]

    current_release = contract.get("current_release")
    next_release = contract.get("next_release")
    if not released:
        failures.append("roadmap must identify at least one released milestone")
    elif current_release != released[-1]:
        failures.append(
            f"current_release must equal the last released milestone {released[-1]}, found {current_release!r}"
        )
    if not planned:
        failures.append("roadmap must identify at least one planned milestone")
    elif next_release != planned[0]:
        failures.append(
            f"next_release must equal the first planned milestone {planned[0]}, found {next_release!r}"
        )

    canonical_document = contract.get("canonical_document")
    domain_document = contract.get("domain_document")
    development_document = contract.get("development_document")
    versioning_document = contract.get("versioning_document")

    def read_contract_document(value: object, label: str) -> str:
        if not isinstance(value, str):
            failures.append(f"{label} must be a string path")
            return ""
        path = root / value
        if not path.is_file():
            failures.append(f"{label} missing: {value}")
            return ""
        return path.read_text(encoding="utf-8")

    roadmap_text = read_contract_document(canonical_document, "canonical_document")
    domain_text = read_contract_document(domain_document, "domain_document")
    development_text = read_contract_document(development_document, "development_document")
    versioning_text = read_contract_document(versioning_document, "versioning_document")

    for version, milestone in by_version.items():
        title = milestone.get("title")
        if isinstance(title, str) and roadmap_text:
            heading = f"## {version} — {title}"
            if heading not in roadmap_text:
                failures.append(f"canonical roadmap missing exact heading: {heading}")

        if milestone.get("status") == "released":
            release_contract = milestone.get("release_contract")
            if not isinstance(release_contract, str):
                failures.append(f"{version}: released milestone must name release_contract")
            elif not (root / release_contract).is_file():
                failures.append(f"{version}: release contract does not exist: {release_contract}")

        qualification = milestone.get("qualification")
        if qualification is not None:
            if not isinstance(qualification, str) or not (root / qualification).is_file():
                failures.append(f"{version}: qualification document does not exist: {qualification!r}")

    def dependency_closure(version: str) -> set[str]:
        visited: set[str] = set()
        stack = list(by_version.get(version, {}).get("depends_on", []))
        while stack:
            dependency = stack.pop()
            if not isinstance(dependency, str) or dependency in visited:
                continue
            visited.add(dependency)
            nested = by_version.get(dependency, {}).get("depends_on", [])
            if isinstance(nested, list):
                stack.extend(nested)
        return visited

    # These are deliberate architectural gates, not estimates. Changing them requires
    # an explicit roadmap rebaseline rather than silently moving product authority earlier.
    expected_gates = {
        "v0.0.0": (False, "none", False, "none", "none", "none"),
        "v0.1.0": (False, "none", False, "none", "none", "none"),
        "v0.2.0": (False, "none", False, "none", "none", "none"),
        "v0.3.0": (False, "none", False, "none", "none", "none"),
        "v0.4.0": (True, "none", False, "none", "none", "none"),
        "v0.5.0": (True, "isolated-qualified", False, "none", "none", "none"),
        "v0.6.0": (True, "integrated-narrow", True, "narrow-experimental", "none", "none"),
        "v0.7.0": (True, "integrated-narrow", True, "narrow-experimental", "none", "none"),
        "v0.8.0": (True, "integrated-narrow", True, "narrow-experimental", "proposal-only", "none"),
        "v0.9.0": (
            True,
            "integrated-narrow",
            True,
            "narrow-experimental",
            "proposal-only",
            "reference-experimental",
        ),
        "v0.10.0": (
            True,
            "integrated-narrow",
            True,
            "reference-experimental",
            "proposal-only",
            "reference-experimental",
        ),
        "v1.0.0": (
            True,
            "integrated-narrow",
            True,
            "reference-stable",
            "proposal-only",
            "reference-stable",
        ),
    }
    if set(by_version) != set(expected_gates):
        failures.append(
            "roadmap milestone set changed; perform an explicit roadmap-contract rebaseline and update checker gates"
        )
    for version, expected in expected_gates.items():
        milestone = by_version.get(version)
        if milestone is None:
            continue
        actual = (
            milestone.get("durable_recovery"),
            milestone.get("executor_state"),
            milestone.get("complete_lifecycle"),
            milestone.get("managed_mutation_support"),
            milestone.get("agent_role"),
            milestone.get("platform_support"),
        )
        if actual != expected:
            failures.append(f"{version}: architectural gate changed from {expected} to {actual}")

    for version, milestone in by_version.items():
        closure = dependency_closure(version)
        durable_recovery = milestone.get("durable_recovery") is True
        executor_state = milestone.get("executor_state")
        complete_lifecycle = milestone.get("complete_lifecycle") is True
        mutation_support = milestone.get("managed_mutation_support")
        platform_support = milestone.get("platform_support")
        claim_class = milestone.get("claim_class")

        if durable_recovery and version != "v0.4.0" and "v0.4.0" not in closure:
            failures.append(f"{version}: durable recovery requires the v0.4.0 foundation")
        if executor_state in {"isolated-qualified", "integrated-narrow"} and not durable_recovery:
            failures.append(f"{version}: executor qualification requires durable recovery semantics")
        if executor_state == "integrated-narrow" and "v0.5.0" not in closure:
            failures.append(f"{version}: integrated executor requires v0.5.0 isolated executor/verifier qualification")
        if complete_lifecycle:
            if not durable_recovery or executor_state != "integrated-narrow":
                failures.append(f"{version}: complete lifecycle requires durable recovery and integrated narrow executor")
            if version != "v0.6.0" and "v0.6.0" not in closure:
                failures.append(f"{version}: complete lifecycle requires the v0.6.0 integration milestone")
        if mutation_support != "none":
            if not complete_lifecycle:
                failures.append(f"{version}: supported managed mutation requires complete lifecycle proof")
            if executor_state != "integrated-narrow":
                failures.append(f"{version}: supported managed mutation requires an integrated narrow executor")
            if not durable_recovery:
                failures.append(f"{version}: supported managed mutation requires durable recovery")
            if version != "v0.6.0" and "v0.6.0" not in closure:
                failures.append(f"{version}: supported managed mutation cannot precede v0.6.0")
        if mutation_support == "reference-experimental" and claim_class != "Experimental":
            failures.append(f"{version}: Experimental reference mutation support requires an Experimental milestone claim")
        if mutation_support == "reference-stable":
            if claim_class != "Stable":
                failures.append(f"{version}: Stable mutation support requires a Stable milestone claim")
            if platform_support != "reference-stable":
                failures.append(f"{version}: Stable mutation support requires a Stable reference platform")
            if "v0.10.0" not in closure:
                failures.append(f"{version}: Stable mutation support requires the v0.10.0 Experimental end-user milestone")
        if milestone.get("agent_role") == "proposal-only" and "v0.7.0" not in closure:
            failures.append(f"{version}: agent interpretation requires the persistent trusted core through v0.7.0")
        if platform_support == "reference-experimental" and "v0.8.0" not in closure:
            failures.append(f"{version}: Experimental reference platform support requires the v0.8.0 proposal boundary")
        if platform_support == "reference-stable":
            if claim_class != "Stable":
                failures.append(f"{version}: Stable reference platform support requires a Stable milestone claim")
            if "v0.10.0" not in closure:
                failures.append(f"{version}: Stable reference platform support requires v0.10.0 experience evidence")

    v010 = by_version.get("v0.10.0")
    if v010 is not None:
        if v010.get("claim_class") != "Experimental":
            failures.append("v0.10.0 must remain the explicitly Experimental end-user milestone")
        if v010.get("experience_scope") != "complete-daily-usable-workstation":
            failures.append("v0.10.0 experience_scope must remain complete-daily-usable-workstation")
        if v010.get("desktop_shell_scope") != "complete-first-party-workstation-shell":
            failures.append("v0.10.0 desktop_shell_scope must remain complete-first-party-workstation-shell")
        if v010.get("installation_scope") != "bounded-qualified-install-plus-adoption":
            failures.append("v0.10.0 installation_scope must remain bounded-qualified-install-plus-adoption")
        if v010.get("daily_use_target") is not True:
            failures.append("v0.10.0 daily_use_target must remain true")
        if v010.get("product_scope_adr") != V010_PRODUCT_SCOPE_ADR:
            failures.append("v0.10.0 product_scope_adr must bind ADR 0033")
        elif not (root / V010_PRODUCT_SCOPE_ADR).is_file():
            failures.append("v0.10 product-scope ADR 0033 is missing")
        if v010.get("slice_contract") != V010_SLICE_CONTRACT:
            failures.append("v0.10.0 slice_contract must bind the canonical 32-slice ledger")
        failures.extend(validate_v010_slice_contract(root, v010.get("status")))
        if _v010_release_gate_required(
            root,
            v010.get("status"),
            contract.get("next_release"),
        ):
            failures.extend(validate_v010_release_readiness(root))
            failures.extend(
                f"v0.10 semantic qualification: {failure}"
                for failure in validate_v010_workstation_qualification(root)
            )

    v1 = by_version.get("v1.0.0")
    if v1 is not None:
        if v1.get("claim_class") != "Stable":
            failures.append("v1.0.0 is reserved for the first Stable supported end-user contract")
        if v1.get("depends_on") != ["v0.10.0"]:
            failures.append("v1.0.0 must follow the v0.10.0 Experimental end-user milestone")

    required_versioning_markers = (
        "`v1.0.0` is the first stable end-user contract.",
        "The 1.0 release contract must have evidence appropriate to a stable system layer",
        "After 1.0, normal Semantic Versioning applies",
    )
    for marker in required_versioning_markers:
        if versioning_text and marker not in versioning_text:
            failures.append(f"versioning policy missing Stable v1 invariant: {marker}")

    required_development_markers = (
        "## Phase 5 — first narrow privileged executor and independent verifier (target v0.5.0)",
        "**Phase 5 remains qualification-only:**",
        "Phase 6 is the first milestone allowed to publish a bounded Experimental supported managed external effect.",
        "## Phase 10 — complete Experimental Linura workstation (target v0.10.0)",
        "## Phase 11 — Stable support qualification (target v1.0.0)",
        "`v1.0.0` is reserved by Linura's versioning policy for the first Stable supported end-user contract.",
        "## Phase 12 — broader system domains (post-v1 strategic expansion)",
    )
    for marker in required_development_markers:
        if development_text and marker not in development_text:
            failures.append(f"development plan missing roadmap alignment marker: {marker}")

    required_roadmap_markers = (
        "## v0.10.0 — complete Experimental Linura workstation",
        "## v1.0.0 — first Stable supported end-user Linura",
        "## Beyond v1.0 — broader support and product expansion",
        "## Post-v1 strategic tracks",
        "### Personal operating environment",
        "### Extension and sharing ecosystem",
        "### General-purpose provider breadth",
        "### Optional fleet and enterprise",
        "## Independent maturity axes",
        "## VM and virtualization boundary",
        "## Dependency gates",
        "## Anti-drift governance",
        "## Roadmap-change procedure",
        "Code presence is not support",
        "Models are untrusted proposers",
        "v0.5 may exercise a narrow executor/verifier only through disposable qualification authority",
        "no supported managed external mutation may appear before v0.6",
        "v1.0 is reserved for the first Stable supported end-user contract",
        "Complete product scope at v0.10 does not imply Stable support",
        "contracts/v010-workstation-slices.toml",
        CANONICAL_LIFECYCLE,
    )
    for marker in required_roadmap_markers:
        if roadmap_text and marker not in roadmap_text:
            failures.append(f"canonical roadmap missing governance marker: {marker}")

    required_domain_markers = (
        "## VM qualification versus VM management",
        "test infrastructure, not a product virtualization capability",
        "libvirt/QEMU/KVM, Incus",
        "→ validate\n→ authorize\n→ prepare\n→ execute through a narrow provider executor\n→ verify through independent re-observation\n→ commit\n→ audit\n→ reconcile",
    )
    for marker in required_domain_markers:
        if domain_text and marker not in domain_text:
            failures.append(f"system domain map missing virtualization boundary marker: {marker}")

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("roadmap contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
