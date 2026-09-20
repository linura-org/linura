#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

CONTRACT_PATH = "contracts/operation-semantics.toml"
ADR_PATH = "docs/adr/0032-classify-operations-before-authority.md"
DOC_PATH = "docs/operation-semantics.md"
CORE_PATH = "crates/linura-core/src/lib.rs"
DESCRIPTOR_PATH = "crates/linura-capability-sdk/src/lib.rs"
CONTROL_OPERATION_PATH = "crates/linura-control/src/operation_semantics.rs"
SECURITY_PATH = "SECURITY.md"
MILESTONE_PATH = "docs/milestones/v0.10.0.md"
QUALIFICATION_PATH = "docs/qualification/v0.10.0.md"
UI_ARCHITECTURE_PATH = "docs/ui-architecture.md"
AGENTS_PATH = "AGENTS.md"
POLICY_GUIDE_PATH = "agents/skills/policy.md"
README_PATH = "README.md"

EXPECTED_MANAGED_LIFECYCLE = ["request", "observe", "plan", "validate", "authorize", "prepare", "execute", "verify", "commit", "audit", "reconcile"]
EXPECTED_TRANSIENT_LIFECYCLE = ["request", "observe", "plan", "validate-classify", "authorize", "execute", "verify", "audit"]
EXPECTED_CLASSES = {
    "experience-ephemeral": {"rust_variant": "ExperienceEphemeral", "changes_external_state": True, "changes_linura_durable_state": False, "control_mediated": False, "risk_classification_required": False, "plan_bound_authorization": False, "privileged_executor_allowed": False, "canonical_managed_lifecycle": False, "path": "experience-local"},
    "authoritative-query": {"rust_variant": "AuthoritativeQuery", "changes_external_state": False, "changes_linura_durable_state": False, "control_mediated": True, "risk_classification_required": False, "plan_bound_authorization": False, "privileged_executor_allowed": False, "canonical_managed_lifecycle": False, "path": "observation-query"},
    "linura-owned-state": {"rust_variant": "LinuraOwnedState", "changes_external_state": False, "changes_linura_durable_state": True, "control_mediated": True, "risk_classification_required": True, "plan_bound_authorization": False, "privileged_executor_allowed": False, "canonical_managed_lifecycle": False, "path": "linura-local-transaction"},
    "transient-external-effect": {"rust_variant": "TransientExternalEffect", "changes_external_state": True, "changes_linura_durable_state": False, "control_mediated": True, "risk_classification_required": True, "plan_bound_authorization": True, "privileged_executor_allowed": False, "canonical_managed_lifecycle": False, "path": "bounded-transient-effect"},
    "managed-external-effect": {"rust_variant": "ManagedExternalEffect", "changes_external_state": True, "changes_linura_durable_state": True, "control_mediated": True, "risk_classification_required": True, "plan_bound_authorization": True, "privileged_executor_allowed": True, "canonical_managed_lifecycle": True, "path": "canonical-managed-mutation"},
}
EXPECTED_RUST_VARIANTS = [value["rust_variant"] for value in EXPECTED_CLASSES.values()]
ENUM_RE = re.compile(r"pub enum OperationClass\s*\{(?P<body>[^}]*)\}", re.DOTALL)


def _load_toml(path: Path, failures: list[str]) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        failures.append(f"missing or non-regular operation-semantics contract: {path}")
        return {}
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        failures.append(f"invalid operation-semantics contract: {error}")
        return {}
    if not isinstance(value, dict):
        failures.append("operation-semantics contract root must be a table")
        return {}
    return value


def _rust_operation_variants(text: str) -> list[str]:
    match = ENUM_RE.search(text)
    if match is None:
        return []
    variants: list[str] = []
    for raw in match.group("body").split(","):
        candidate = raw.strip().split("=", 1)[0].strip()
        if candidate and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", candidate):
            variants.append(candidate)
    return variants


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract = _load_toml(root / CONTRACT_PATH, failures)
    if not contract:
        if not failures:
            failures.append("operation-semantics contract must not be empty")
        return failures
    expected_root = {
        "schema_version": 1,
        "architecture_decision": ADR_PATH,
        "documentation": DOC_PATH,
        "core_type": "linura_core::OperationClass",
        "descriptor_type": "linura_capability_sdk::OperationDescriptor",
        "effect_binding_type": "linura_capability_sdk::OperationEffectBinding",
        "operation_registry_type": "linura_capability_sdk::OperationRegistry",
        "external_operation_resolution_type": "linura_control::OperationSemanticsControl",
        "risk_type": "linura_core::RiskClass",
        "classification_owner": "trusted-operation-registry-and-linura-control",
        "client_classification_authority": False,
        "provider_classification_authority": False,
        "unknown_effect_behavior": "fail-closed",
        "risk_model": "orthogonal",
        "privileged_effect_class": "managed-external-effect",
        "policy_subject_type": "linura_policy::PolicySubject",
        "policy_plan_type": "linura_planner::ReconciliationPlan",
        "external_effect_authorization_binding": "canonical-plan-plus-authenticated-principal",
        "external_effect_plan_shape_binding": "registered-provider-capability-resource-scope-change-keys",
        "transient_external_max_risk": "user-state",
        "transient_durable_prepare_required": False,
        "transient_failure_model": "bounded-reobserve-no-durable-indeterminate-recovery",
        "managed_lifecycle": EXPECTED_MANAGED_LIFECYCLE,
        "transient_effect_lifecycle": EXPECTED_TRANSIENT_LIFECYCLE,
    }
    for key, expected in expected_root.items():
        if contract.get(key) != expected:
            failures.append(f"operation-semantics {key} drifted from the canonical contract")
    classes = contract.get("classes")
    if not isinstance(classes, dict):
        failures.append("operation-semantics contract missing classes")
    elif classes != EXPECTED_CLASSES:
        failures.append("operation-semantics classes drifted from the canonical contract")
    required_files = (
        (ADR_PATH, "ADR 0032"),
        (DOC_PATH, "operation semantics documentation"),
        (CORE_PATH, "OperationClass core type"),
        (DESCRIPTOR_PATH, "OperationDescriptor/OperationRegistry types"),
        (CONTROL_OPERATION_PATH, "Control operation-semantics resolver"),
        (SECURITY_PATH, "security policy"),
        (MILESTONE_PATH, "v0.10 milestone"),
        (QUALIFICATION_PATH, "v0.10 qualification"),
        (UI_ARCHITECTURE_PATH, "UI architecture"),
        (AGENTS_PATH, "agent contribution contract"),
        (POLICY_GUIDE_PATH, "policy task guide"),
        (README_PATH, "repository README"),
    )
    for path, label in required_files:
        candidate = root / path
        if not candidate.is_file() or candidate.is_symlink():
            failures.append(f"missing or non-regular {label}: {path}")

    required_markers = {
        SECURITY_PATH: (
            "Prepare before managed external effects.",
            "A qualified `TransientExternalEffect` is deliberately exempt from durable prepare",
        ),
        MILESTONE_PATH: (
            "every supported `ManagedExternalEffect` workstation mutation has narrow typed authority, durable prepare/recovery and independent verification",
            "claimed `TransientExternalEffect` operations satisfy their separate bounded no-durable-prepare contract",
        ),
        QUALIFICATION_PATH: (
            "A qualified `TransientExternalEffect` instead follows the machine-readable bounded transient lifecycle",
            "has no durable prepare/commit/reconcile transaction",
        ),
        UI_ARCHITECTURE_PATH: (
            "every external effect that reaches policy authorization is plan-bound",
            "a qualified `TransientExternalEffect` may use the bounded Control-mediated transient lifecycle",
        ),
        AGENTS_PATH: (
            "including qualified `TransientExternalEffect` operations",
            "after the same canonical plan-bound authorization",
        ),
        POLICY_GUIDE_PATH: (
            "both managed and qualified transient external effects",
            "including `TransientExternalEffect`",
        ),
        README_PATH: (
            "Supported `ManagedExternalEffect` operations require durable pre-execution prepare/recovery state.",
            "A qualified `TransientExternalEffect` is the narrow exception defined by the operation-semantics contract",
        ),
    }
    forbidden_markers = {
        README_PATH: (
            "External effects are never supported without a durable pre-execution recovery record.",
            "External effects require durable pre-execution prepare/recovery state.",
        ),
    }
    for path, markers in forbidden_markers.items():
        candidate = root / path
        if not candidate.is_file() or candidate.is_symlink():
            continue
        text = candidate.read_text(encoding="utf-8")
        for marker in markers:
            if marker in text:
                failures.append(f"{path} contains forbidden operation-semantics marker: {marker}")

    for path, markers in required_markers.items():
        candidate = root / path
        if not candidate.is_file() or candidate.is_symlink():
            continue
        text = candidate.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                failures.append(f"{path} missing operation-semantics marker: {marker}")
    core_path = root / CORE_PATH
    if core_path.is_file() and not core_path.is_symlink():
        variants = _rust_operation_variants(core_path.read_text(encoding="utf-8"))
        if variants != EXPECTED_RUST_VARIANTS:
            failures.append("linura_core::OperationClass variants drifted from the machine-readable contract")
    descriptor_path = root / DESCRIPTOR_PATH
    if descriptor_path.is_file() and not descriptor_path.is_symlink():
        descriptor = descriptor_path.read_text(encoding="utf-8")
        for fragment in ("pub struct OperationDescriptor", "pub struct OperationEffectBinding", "pub struct OperationRegistry", "MissingEffectBinding", "DuplicateOperation", "effect_binding", "OperationClass", "RiskClass", "pub fn try_new"):
            if fragment not in descriptor:
                failures.append(f"linura_capability_sdk::OperationDescriptor missing required fragment: {fragment}")
    control_operation_path = root / CONTROL_OPERATION_PATH
    if control_operation_path.is_file() and not control_operation_path.is_symlink():
        control_operation = control_operation_path.read_text(encoding="utf-8")
        for fragment in (
            "pub struct OperationSemanticsControl",
            "pub fn resolve_external",
            "classify_plan_risk",
            "TransientRiskExceedsBoundary",
            "pub enum OperationPlanBindingMismatch",
        ):
            if fragment not in control_operation:
                failures.append(
                    f"linura_control::OperationSemanticsControl missing required fragment: {fragment}"
                )
    core_text = core_path.read_text(encoding="utf-8") if core_path.is_file() and not core_path.is_symlink() else ""
    if "requires_plan_bound_external_authorization" not in core_text:
        failures.append("linura_core::OperationClass missing plan-bound external authorization invariant")
    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("operation semantics contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
