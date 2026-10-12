#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys
import tomllib

EXPECTED_AUTHORITY_STATES = {
    "v0.0.0": "none",
    "v0.1.0": "none",
    "v0.2.0": "none",
    "v0.3.0": "review-only",
    "v0.4.0": "durable-reviewed",
    "v0.5.0": "durable-reviewed",
    "v0.6.0": "lifecycle-integrated",
    "v0.7.0": "lifecycle-integrated",
    "v0.8.0": "lifecycle-integrated",
    "v0.9.0": "lifecycle-integrated",
    "v0.10.0": "lifecycle-integrated",
    "v1.0.0": "lifecycle-integrated",
}
VALID_AUTHORITY_STATES = {
    "none",
    "review-only",
    "durable-reviewed",
    "lifecycle-integrated",
}

REMOVED_BOOTSTRAP_MARKERS = {
    "crates/linura-core/src/lib.rs": (
        "pub struct ActionPlan",
        "pub struct Effect",
        "pub enum Compensation",
    ),
    "crates/linura-protocol/src/lib.rs": (
        "pub struct ActionRequest",
        "pub enum PlanResponse",
    ),
    "crates/linura-provider-sdk/src/lib.rs": (
        "pub struct Observation {",
        "pub trait Provider:",
        "pub trait EffectExecutor",
        "pub trait EffectVerifier",
    ),
    "crates/linura-control/src/lib.rs": (
        "pub trait MutationRuntime",
        "pub struct ControlPlane<",
        "pub fn apply<",
    ),
}

PRESERVED_SCAFFOLD_MARKERS = {
    "crates/linura-lifecycle/src/lib.rs": (
        "pub const MUTATION_STAGES: [MutationStage; 11]",
        "MutationStage::Authorize",
        "MutationStage::Prepare",
        "MutationStage::Execute",
        "MutationStage::Verify",
        "MutationStage::Commit",
        "MutationStage::Audit",
        "MutationStage::Reconcile",
    ),
    "executors/linura-executor-systemd/src/lib.rs": (
        "pub enum SystemdOperation",
        "SetUnitEnabled",
        "RestartUnit",
    ),
    "crates/linura-provider-sdk/src/lib.rs": (
        "pub trait Observer",
        "Result<ObservationEnvelope, ProviderError>",
    ),
    "crates/linura-planner/src/lib.rs": (
        "pub struct ReconciliationPlan",
        "ExecutionAuthority::Disabled",
    ),
    "crates/linura-control/src/risk_classification.rs": (
        "BASELINE_RISK_POLICY_REVISION",
        "return RiskClassification::Unclassified {",
        "return RiskClassification::DowngradeRejected {",
        "systemd.unit.active-state.security-sensitive",
        "no trusted risk rule covers",
    ),
    "crates/linura-control/src/policy_review.rs": (
        "classify_plan_risk(plan)",
        'code: "authority-risk-classified".into()',
        'code: "authority-risk-unclassified".into()',
        'code: "authority-risk-downgrade-rejected".into()',
    ),
}

# Runtime policy semantics are intentionally verified by an executable Rust
# contract test, not by attempting to parse/evaluate Rust with this Python
# architecture checker. `cargo test --workspace` is part of canonical checks,
# so changes to production control flow, guarded arms, early returns, or nested
# expressions are exercised as behavior rather than guessed from source text.
SEMANTIC_APPROVAL_TEST_MARKERS = (
    "fn protected_approval_strength_is_actor_invariant()",
    "ActorKind::Human",
    "ActorKind::Service",
    "ActorKind::Agent",
    "RiskClass::SystemMutation, ApprovalClass::InteractiveUser",
    "RiskClass::SecuritySensitive, ApprovalClass::Administrator",
    "RiskClass::Destructive, ApprovalClass::DestructiveAction",
    "fn remote_actor_cannot_use_protected_approval_path()",
)

REQUIRED_V03_MARKERS = {
    "docs/milestones/v0.3.0.md": (
        "v0.3 extends the v0.2 `linura-planner::ReconciliationPlan` lineage.",
        "The planner's `prospective_risk` is a risk floor.",
        "Unclassified mutation risk fails closed as `blocked`",
        "Approval does not create execution authority.",
        "A reviewed plan does not create a durable prepare record.",
    ),
    "docs/qualification/v0.3.0.md": (
        "qualification specification",
        "risk-policy revision and matched rule identities",
        "risk downgrade below the planner floor is rejected",
        "A plan ID by itself is not sufficient authority evidence.",
        "native Linux state remains unchanged",
    ),
    "docs/adr/0018-canonical-plan-review-authority.md": (
        "The planner's `prospective_risk` is a lower bound",
        "Unknown mutation shapes fail closed",
        "policy allow          != execution authority",
        "valid approval        != execution authority",
        "reviewed plan         != prepared mutation",
    ),
    "docs/threat-model.md": (
        "### Risk downgrade, under-classification or classifier substitution",
        "no matching trusted rule means unclassified mutation risk",
        "### Approval replay, theft or policy substitution",
        "cross-principal approval reuse",
    ),
}


def read_text(root: Path, relative: str, failures: list[str]) -> str:
    path = root / relative
    if not path.is_file():
        failures.append(f"required authority-foundation file missing: {relative}")
        return ""
    return path.read_text(encoding="utf-8")


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract_path = root / "contracts/roadmap.toml"
    if not contract_path.is_file():
        return ["missing contracts/roadmap.toml"]

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"invalid contracts/roadmap.toml: {error}"]

    milestones = contract.get("milestone")
    if not isinstance(milestones, list):
        return ["roadmap contract milestone must be a list"]

    by_version: dict[str, dict[str, object]] = {}
    for milestone in milestones:
        if not isinstance(milestone, dict):
            failures.append("roadmap milestone must be a table")
            continue
        version = milestone.get("version")
        if not isinstance(version, str):
            failures.append("roadmap milestone version must be a string")
            continue
        by_version[version] = milestone
        authority_state = milestone.get("authority_state")
        if authority_state not in VALID_AUTHORITY_STATES:
            failures.append(
                f"{version}: unsupported authority_state {authority_state!r}"
            )

    if set(by_version) != set(EXPECTED_AUTHORITY_STATES):
        failures.append(
            "authority milestone set changed; explicitly rebaseline authority-state expectations"
        )
    for version, expected in EXPECTED_AUTHORITY_STATES.items():
        milestone = by_version.get(version)
        if milestone is None:
            continue
        actual = milestone.get("authority_state")
        if actual != expected:
            failures.append(
                f"{version}: authority_state must remain {expected!r}, found {actual!r}"
            )

    v03 = by_version.get("v0.3.0")
    if v03 is not None:
        if v03.get("durable_recovery") is not False:
            failures.append(
                "v0.3.0 review-only authority must not claim durable recovery"
            )
        if v03.get("executor_state") != "none":
            failures.append("v0.3.0 review-only authority must not carry an executor")
        if v03.get("complete_lifecycle") is not False:
            failures.append(
                "v0.3.0 review-only authority must not claim complete lifecycle"
            )
        if v03.get("managed_mutation_support") != "none":
            failures.append(
                "v0.3.0 review-only authority must not support managed mutation"
            )
        if v03.get("milestone_contract") != "docs/milestones/v0.3.0.md":
            failures.append("v0.3.0 must bind docs/milestones/v0.3.0.md")

    for version in ("v0.4.0", "v0.5.0"):
        milestone = by_version.get(version)
        if milestone is not None and milestone.get("durable_recovery") is not True:
            failures.append(
                f"{version}: durable-reviewed authority requires durable recovery"
            )

    for version in (
        "v0.6.0",
        "v0.7.0",
        "v0.8.0",
        "v0.9.0",
        "v0.10.0",
        "v1.0.0",
    ):
        milestone = by_version.get(version)
        if milestone is None:
            continue
        if milestone.get("complete_lifecycle") is not True:
            failures.append(
                f"{version}: lifecycle-integrated authority requires complete lifecycle"
            )
        if milestone.get("executor_state") != "integrated-narrow":
            failures.append(
                f"{version}: lifecycle-integrated authority requires integrated narrow executor"
            )

    for relative, markers in REMOVED_BOOTSTRAP_MARKERS.items():
        text = read_text(root, relative, failures)
        for marker in markers:
            if marker in text:
                failures.append(
                    f"superseded bootstrap authority marker reintroduced in {relative}: {marker}"
                )

    for relative, markers in PRESERVED_SCAFFOLD_MARKERS.items():
        text = read_text(root, relative, failures)
        for marker in markers:
            if marker not in text:
                failures.append(
                    f"future authority scaffold missing from {relative}: {marker}"
                )

    semantic_test_path = "crates/linura-policy/tests/approval_strength.rs"
    semantic_test = read_text(root, semantic_test_path, failures)
    for marker in SEMANTIC_APPROVAL_TEST_MARKERS:
        if marker not in semantic_test:
            failures.append(
                f"executable approval-strength contract marker missing from {semantic_test_path}: {marker}"
            )

    for relative, markers in REQUIRED_V03_MARKERS.items():
        text = read_text(root, relative, failures)
        for marker in markers:
            if marker not in text:
                failures.append(
                    f"v0.3 authority contract marker missing from {relative}: {marker}"
                )

    return failures


def main(argv: list[str]) -> int:
    root = (
        Path(argv[1]).resolve()
        if len(argv) > 1
        else Path(__file__).resolve().parents[1]
    )
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("authority foundation checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
