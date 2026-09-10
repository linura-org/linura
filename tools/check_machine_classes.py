#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys
import tomllib

EXPECTED_MACHINE_CLASSES = ("workstation", "server", "edge")
EXPECTED_FLEET_MODEL = "optional-overlay"


def _read_text(root: Path, value: object, label: str, failures: list[str]) -> str:
    if not isinstance(value, str) or not value:
        failures.append(f"{label} must be a non-empty string path")
        return ""
    path = root / value
    if not path.is_file():
        failures.append(f"{label} missing: {value}")
        return ""
    return path.read_text(encoding="utf-8")


def _read_json(root: Path, relative: str, label: str, failures: list[str]) -> dict[str, object]:
    path = root / relative
    if not path.is_file():
        failures.append(f"{label} missing: {relative}")
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        failures.append(f"invalid {label}: {error}")
        return {}
    if not isinstance(loaded, dict):
        failures.append(f"{label} root must be an object")
        return {}
    return loaded


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract_path = root / "contracts/roadmap.toml"
    if not contract_path.is_file():
        return ["missing contracts/roadmap.toml"]

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as error:
        return [f"invalid contracts/roadmap.toml: {error}"]

    machine_classes = contract.get("target_machine_classes")
    if machine_classes != list(EXPECTED_MACHINE_CLASSES):
        failures.append(
            "target_machine_classes must remain exactly workstation, server, edge; "
            f"found {machine_classes!r}"
        )

    fleet_model = contract.get("fleet_model")
    if fleet_model != EXPECTED_FLEET_MODEL:
        failures.append(
            "fleet_model must remain optional-overlay so fleet cannot replace local machine authority; "
            f"found {fleet_model!r}"
        )

    roadmap_text = _read_text(
        root,
        contract.get("canonical_document"),
        "canonical_document",
        failures,
    )
    machine_profile_text = _read_text(
        root,
        contract.get("machine_profile_document"),
        "machine_profile_document",
        failures,
    )
    domain_text = _read_text(
        root,
        contract.get("domain_document"),
        "domain_document",
        failures,
    )

    support_path_value = contract.get("hardware_support_matrix")
    support: dict[str, object] = {}
    if not isinstance(support_path_value, str) or not support_path_value:
        failures.append("hardware_support_matrix must be a non-empty string path")
    else:
        support = _read_json(root, support_path_value, "hardware support matrix", failures)

    required_roadmap_markers = (
        "Machine classes are support targets, not domains.",
        "### Machine-class expansion",
        "| Machine/platform support | Which exact workstation/server/edge + distribution/desktop-or-headless/architecture/hardware profiles are release-qualified? |",
        "## Target machine classes",
        "The canonical target classes are `workstation`, `server` and `edge`",
        "A **developer machine** is normally a workstation profile, not a fourth machine class.",
        "Fleet/enterprise** is an optional management/control topology",
        "Machine classes do not become domains or fleet roles.",
    )
    for marker in required_roadmap_markers:
        if roadmap_text and marker not in roadmap_text:
            failures.append(f"canonical roadmap missing machine-class invariant: {marker}")

    required_profile_markers = (
        "## Target machine classes",
        "**workstation**",
        "**server**",
        "**edge**",
        "`developer machine` is not a fourth class",
        "## Machine class is orthogonal to system domains",
        "Domain capability maturity remains tracked by D0–D7",
        "## Fleet is an optional overlay, not a machine class",
        "Fleet services never become a fourth machine class",
        "## Class-specific qualification concerns",
        "### Workstation",
        "### Server",
        "### Edge",
    )
    for marker in required_profile_markers:
        if machine_profile_text and marker not in machine_profile_text:
            failures.append(f"machine profile document missing machine-class invariant: {marker}")

    required_domain_markers = (
        "## Machine-class applicability",
        "Workstation, server and edge are **machine classes**, not domains and not replacements for D0–D7.",
        "| Domain | Workstation | Server | Edge |",
        "| Remote/fleet | optional overlay | optional overlay | optional overlay |",
        "They are **not maturity or support levels**.",
        "Fleet is intentionally shown as an optional overlay for every class.",
        "Do not create a second D-like maturity ladder for workstation/server/edge.",
    )
    for marker in required_domain_markers:
        if domain_text and marker not in domain_text:
            failures.append(f"system domain map missing machine-class invariant: {marker}")

    support_classes = support.get("machine_classes") if support else None
    if not isinstance(support_classes, dict):
        failures.append("hardware support matrix must define machine_classes as an object")
    else:
        if tuple(support_classes.keys()) != EXPECTED_MACHINE_CLASSES:
            failures.append(
                "hardware support matrix machine_classes must remain exactly workstation, server, edge "
                f"in canonical order; found {tuple(support_classes.keys())!r}"
            )
        if "fleet" in support_classes:
            failures.append("fleet must not appear as a hardware support machine class")

        for machine_class in EXPECTED_MACHINE_CLASSES:
            entry = support_classes.get(machine_class)
            if not isinstance(entry, dict):
                failures.append(f"machine class {machine_class} support entry must be an object")
                continue
            profiles = entry.get("release_qualified_profiles")
            if not isinstance(profiles, list) or not all(
                isinstance(profile, str) and profile.strip() for profile in profiles
            ):
                failures.append(
                    f"machine class {machine_class} release_qualified_profiles must be an array of non-empty strings"
                )
                continue
            if len(profiles) != len(set(profiles)):
                failures.append(f"machine class {machine_class} release_qualified_profiles contains duplicates")

    milestones = contract.get("milestone")
    current_release = contract.get("current_release")
    current_platform_support: object = None
    if isinstance(milestones, list) and isinstance(current_release, str):
        for milestone in milestones:
            if isinstance(milestone, dict) and milestone.get("version") == current_release:
                current_platform_support = milestone.get("platform_support")
                break

    if current_platform_support == "none" and isinstance(support_classes, dict):
        for machine_class in EXPECTED_MACHINE_CLASSES:
            entry = support_classes.get(machine_class)
            if isinstance(entry, dict) and entry.get("release_qualified_profiles"):
                failures.append(
                    f"{machine_class}: current release has platform_support=none, so release_qualified_profiles must remain empty"
                )

    # The typed intent/profile domain and portable schema must preserve machine
    # class end to end. Documentation alone cannot support cross-class adoption
    # checks because replay must retain the source class as data.
    intent_model_path = root / "crates/linura-intent/src/model.rs"
    if not intent_model_path.is_file():
        failures.append("machine-class intent contract missing: crates/linura-intent/src/model.rs")
    else:
        intent_text = intent_model_path.read_text(encoding="utf-8")
        for marker in (
            "pub enum MachineClass",
            "Workstation,",
            "Server,",
            "Edge,",
            "pub machine_class: MachineClass,",
        ):
            if marker not in intent_text:
                failures.append(f"typed machine profile missing machine-class contract marker: {marker}")

    sdk_path = root / "crates/linura-sdk/src/lib.rs"
    if not sdk_path.is_file():
        failures.append("machine-class SDK contract missing: crates/linura-sdk/src/lib.rs")
    else:
        sdk_text = sdk_path.read_text(encoding="utf-8")
        if "MachineClass, MachineProfile" not in sdk_text:
            failures.append("public SDK must re-export MachineClass with MachineProfile")

    portable_schema = _read_json(
        root,
        "schemas/portable-profile.v1.schema.json",
        "portable profile schema",
        failures,
    )
    properties = portable_schema.get("properties") if portable_schema else None
    profile_schema = properties.get("profile") if isinstance(properties, dict) else None
    if not isinstance(profile_schema, dict):
        failures.append("portable profile schema must define properties.profile")
    else:
        required = profile_schema.get("required")
        if not isinstance(required, list) or "machine_class" not in required:
            failures.append("portable profile schema must require profile.machine_class")
        profile_properties = profile_schema.get("properties")
        machine_class_schema = (
            profile_properties.get("machine_class") if isinstance(profile_properties, dict) else None
        )
        if not isinstance(machine_class_schema, dict):
            failures.append("portable profile schema must define profile.machine_class")
        else:
            if machine_class_schema.get("type") != "string":
                failures.append("portable profile profile.machine_class must be a string")
            values = machine_class_schema.get("enum")
            if values != list(EXPECTED_MACHINE_CLASSES):
                failures.append(
                    "portable profile machine_class enum must remain exactly workstation, server, edge; "
                    f"found {values!r}"
                )

    # Intelligence and fleet are orthogonal overlays around locally authoritative
    # workstation/server/edge machines; neither is a local machine class.
    if isinstance(machine_classes, list):
        if "fleet" in machine_classes or "enterprise" in machine_classes:
            failures.append("fleet/enterprise must not be encoded as a local machine class")
        if "agent" in machine_classes or "ai" in machine_classes:
            failures.append("agents/AI must not be encoded as a local machine class")

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("machine-class contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
