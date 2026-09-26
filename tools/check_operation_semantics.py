#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

CONTRACT_PATH = "contracts/operation-semantics.toml"
ADR_PATH = "docs/adr/0032-classify-operations-before-authority.md"
DOC_PATH = "docs/operation-semantics.md"
THREAT_MODEL_PATH = "docs/threat-model.md"
CORE_PATH = "crates/linura-core/src/lib.rs"
DESCRIPTOR_PATH = "crates/linura-capability-sdk/src/lib.rs"
CONTROL_OPERATION_PATH = "crates/linura-control/src/operation_semantics.rs"
CONTROL_REGISTRY_PATH = "crates/linura-control/src/operation_registry.rs"
MANAGED_LIFECYCLE_PATH = "crates/linura-control/src/managed_lifecycle.rs"
DURABLE_AUTHORITY_PATH = "crates/linura-control/src/durable_authority.rs"
RISK_CLASSIFICATION_PATH = "crates/linura-control/src/risk_classification.rs"
POLICY_REVIEW_PATH = "crates/linura-control/src/policy_review.rs"
TRANSIENT_EFFECT_PATH = "crates/linura-control/src/transient_effect.rs"
SESSION_DBUS_PATH = "crates/linura-dbus/src/session.rs"
SESSION_RUNTIME_PATH = "apps/linurad/src/session_audio.rs"
SESSION_AUDIT_PATH = "apps/linurad/src/session_audit.rs"
SESSION_AUDIO_HELPER_PATH = "packaging/wireplumber/linura-session-audio.lua"
ARCH_PROFILE_PATH = "packaging/arch/archiso/profiledef.sh"
LINUX_OBSERVATION_PATH = "crates/linura-linux-observation/src/lib.rs"
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
EXPECTED_REGISTERED_OPERATIONS = {
    "managed-systemd-active-state": {
        "operation_id": "operation:systemd.unit.set-active-state",
        "class": "managed-external-effect",
        "risk_floor": "security-sensitive",
        "risk_floor_rule_id": "operation-registry.managed-systemd-active-state.risk-floor",
        "provider": "systemd",
        "observation_capability": "systemd.unit.observe",
        "resource_prefix": "systemd:unit:linura-managed-",
        "resource_suffix": ".service",
        "change_keys": ["active_state"],
    },
    "transient-audio-session-volume": {
        "operation_id": "operation:audio.output.set-session-volume",
        "class": "transient-external-effect",
        "risk_floor": "user-state",
        "provider": "pipewire",
        "observation_capability": "audio.session.observe",
        "resource_prefix": "audio:session:output:",
        "change_keys": ["volume_percent"],
    },
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
        "managed_handoff_semantics_binding": "registered-operation-before-every-privileged-handoff",
        "registered_risk_floor_authority_binding": "policy-review-and-durable-authority-binding",
        "transient_control_type": "linura_control::TransientEffectControl",
        "transient_risk_refinement": "exact-registered-plan-shape-only",
        "transient_risk_refinement_material_binding": "complete-requested-postcondition",
        "transient_executor_privilege": "unprivileged-only",
        "transient_post_effect_reobserve_required": True,
        "transient_post_effect_order_binding": "strictly-after-dispatch-start",
        "transient_no_change_policy_review_required": True,
        "transient_audit_sink_required": True,
        "transient_requested_postcondition_binding": "complete-requested-state-not-initial-diff",
        "transient_audit_material_binding": "canonical-plan-sha256-plus-requested-postcondition-sha256",
        "transient_audit_authorization_binding": "policy-id-revision-plus-reviewed-risk-plus-risk-classification-revision-rule-ids",
        "transient_audit_diagnostic_binding": "stable-categorical-code-no-executor-or-provider-diagnostic-text",
        "transient_audit_dispatch_binding": "durable-attempt-reservation-before-executor-dispatch",
        "transient_audit_terminal_binding": "reservation-linked-idempotent-terminal-record",
        "transient_session_interface": "dbus.org.linura.Session1",
        "transient_session_composition_owner": "linurad",
        "transient_session_principal_binding": "authenticated-same-uid-as-session-service",
        "transient_session_audit_persistence": "sqlite-wal-full-sync-bounded",
        "transient_session_audit_schema_binding": "exact-strict-schema-single-link-bounded-file",
        "transient_session_audio_native_api": "wireplumber-object-manager-plus-mixer-api",
        "transient_session_audio_helper": "root-owned-packaged-wpexec-script",
        "transient_volatile_resource_identity_binding": "wireplumber-object-identity-resolved-and-mutated-in-one-event-loop-turn",
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
    registered_operations = contract.get("registered_operations")
    if not isinstance(registered_operations, dict):
        failures.append("operation-semantics contract missing registered_operations")
    elif registered_operations != EXPECTED_REGISTERED_OPERATIONS:
        failures.append("operation-semantics registered_operations drifted from the canonical contract")
    required_files = (
        (ADR_PATH, "ADR 0032"),
        (DOC_PATH, "operation semantics documentation"),
        (THREAT_MODEL_PATH, "operation-semantics threat model"),
        (CORE_PATH, "OperationClass core type"),
        (DESCRIPTOR_PATH, "OperationDescriptor/OperationRegistry types"),
        (CONTROL_OPERATION_PATH, "Control operation-semantics resolver"),
        (CONTROL_REGISTRY_PATH, "trusted Control operation registry"),
        (MANAGED_LIFECYCLE_PATH, "managed lifecycle integration"),
        (DURABLE_AUTHORITY_PATH, "durable authority handoff boundary"),
        (RISK_CLASSIFICATION_PATH, "trusted risk classification"),
        (POLICY_REVIEW_PATH, "trusted policy review"),
        (TRANSIENT_EFFECT_PATH, "transient external-effect Control lifecycle"),
        (SESSION_DBUS_PATH, "bounded Session1 transport"),
        (SESSION_RUNTIME_PATH, "PipeWire session-volume runtime"),
        (SESSION_AUDIT_PATH, "durable transient session audit"),
        (SESSION_AUDIO_HELPER_PATH, "trusted WirePlumber session-audio helper"),
        (ARCH_PROFILE_PATH, "Arch workstation image profile"),
        (LINUX_OBSERVATION_PATH, "bounded Linux observation adapters"),
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
        ADR_PATH: (
            "### Registered semantics are authority input",
            "A registered risk floor is applied **before policy review**.",
            "Immediately before every privileged handoff, Control re-resolves the prepared canonical plan",
            "trusted exact registered refinement",
            "linura_control::TransientEffectControl",
        ),
        THREAT_MODEL_PATH: (
            "### Registered-operation substitution or risk-floor weakening",
            "the registered risk floor is applied before policy review",
            "managed restart and `Indeterminate` recovery re-establish authority from current registration",
            "immediately before every privileged handoff, Control re-resolves the prepared plan through the trusted registry",
            "### Transient executor self-report, stale verification or hidden ambiguity",
            "the sole downward-refinement exception is the trusted exact registered transient path",
            "the complete requested postcondition must be covered by the trusted transient risk rule",
            "a durable audit attempt reservation is accepted before executor dispatch",
            "arbitrary executor/provider diagnostic text is never persisted in transient audit records",
        ),
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
            "That substrate is not itself a supported external effect.",
            "Test-only operation descriptors and synthetic observers/executors are architecture qualification, not support activation.",
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
        for fragment in ("pub struct OperationDescriptor", "pub struct OperationEffectBinding", "pub struct OperationRegistry", "MissingEffectBinding", "DuplicateOperation", "effect_binding", "matches_resource", "resource_suffix", "OperationClass", "RiskClass", "pub fn try_new"):
            if fragment not in descriptor:
                failures.append(f"linura_capability_sdk::OperationDescriptor missing required fragment: {fragment}")
    control_operation_path = root / CONTROL_OPERATION_PATH
    if control_operation_path.is_file() and not control_operation_path.is_symlink():
        control_operation = control_operation_path.read_text(encoding="utf-8")
        for fragment in (
            "pub struct OperationSemanticsControl",
            "pub fn resolve_external",
            "classify_plan_risk",
            "classify_exact_registered_transient_risk",
            "TransientRequestedStateRequired",
            "classify_exact_registered_transient_risk(plan, requested_state)",
            "class == OperationClass::TransientExternalEffect",
            "TransientRiskExceedsBoundary",
            "pub enum OperationPlanBindingMismatch",
        ):
            if fragment not in control_operation:
                failures.append(
                    f"linura_control::OperationSemanticsControl missing required fragment: {fragment}"
                )
    registry_path = root / CONTROL_REGISTRY_PATH
    if registry_path.is_file() and not registry_path.is_symlink():
        registry_text = registry_path.read_text(encoding="utf-8")
        for fragment in (
            'MANAGED_SYSTEMD_REGISTERED_OPERATION_ID',
            '"operation:systemd.unit.set-active-state"',
            'OperationClass::ManagedExternalEffect',
            'Some(RiskClass::SecuritySensitive)',
            'MANAGED_SYSTEMD_RESOURCE_PREFIX',
            'MANAGED_SYSTEMD_RESOURCE_SUFFIX',
            'MANAGED_SYSTEMD_RISK_FLOOR_RULE_ID',
            '"operation-registry.managed-systemd-active-state.risk-floor"',
            '.with_resource_suffix(MANAGED_SYSTEMD_RESOURCE_SUFFIX)',
            'vec![MANAGED_SYSTEMD_CHANGE_KEY.into()]',
            'trusted_builtin_operation_registry',
        ):
            if fragment not in registry_text:
                failures.append(
                    f"trusted Control operation registry missing required fragment: {fragment}"
                )
    managed_path = root / MANAGED_LIFECYCLE_PATH
    if managed_path.is_file() and not managed_path.is_symlink():
        managed_text = managed_path.read_text(encoding="utf-8")
        for fragment in (
            'trusted_builtin_operation_registry()',
            'validate_managed_systemd_registration(&operation_semantics)',
            'self.validate_registered_managed_systemd_candidate(&candidate)?',
            'self.validate_registered_managed_systemd_candidate(&refreshed)?',
            'self.handoff_registered_managed_systemd(&principal, &mut prepared)?',
            'self.handoff_registered_managed_systemd(&principal, prepared.as_mut())?',
            'candidate_with_risk_floor',
            'recover_indeterminate_with_risk_floor',
            'recover_indeterminate_with_approver_and_risk_floor',
            'registered_managed_systemd_risk_floor',
            'prepared.binding().trusted_risk()',
            'semantics.risk() != bound_risk',
        ):
            if fragment not in managed_text:
                failures.append(
                    f"managed lifecycle missing trusted operation-registry integration: {fragment}"
                )
        expected_managed_path_counts = {
            "candidate_with_risk_floor(": 2,
            "recover_indeterminate_with_risk_floor(": 3,
            "recover_indeterminate_with_approver_and_risk_floor(": 1,
        }
        for fragment, expected_count in expected_managed_path_counts.items():
            actual_count = managed_text.count(fragment)
            if actual_count != expected_count:
                failures.append(
                    f"managed lifecycle risk-floor path count drifted for {fragment}: "
                    f"expected {expected_count}, found {actual_count}"
                )
    durable_path = root / DURABLE_AUTHORITY_PATH
    if durable_path.is_file() and not durable_path.is_symlink():
        durable_text = durable_path.read_text(encoding="utf-8")
        for fragment in (
            "pub(crate) fn plan(&self) -> &linura_planner::ReconciliationPlan",
            "pub(crate) fn handoff(",
            "candidate_with_risk_floor",
            "recover_indeterminate_with_risk_floor",
            "recover_indeterminate_with_approver_and_risk_floor",
            "review_plan_with_classification",
            "candidate.risk_floor",
            "review.subject().prospective_risk() != risk.risk",
        ):
            if fragment not in durable_text:
                failures.append(
                    f"durable authority handoff boundary missing required fragment: {fragment}"
                )
        expected_review_paths = 3
        actual_review_paths = durable_text.count("review_plan_with_classification(")
        if actual_review_paths != expected_review_paths:
            failures.append(
                "durable authority floored policy-review path count drifted: "
                f"expected {expected_review_paths}, found {actual_review_paths}"
            )
    risk_path = root / RISK_CLASSIFICATION_PATH
    if risk_path.is_file() and not risk_path.is_symlink():
        risk_text = risk_path.read_text(encoding="utf-8")
        for fragment in (
            "REGISTERED_OPERATION_RISK_POLICY_REVISION",
            "REGISTERED_TRANSIENT_RISK_POLICY_REVISION",
            "classify_plan_risk_with_floor",
            "classify_exact_registered_transient_risk",
            "audio.session.output-state.user-state",
            "matches_material_keys",
            "requested_state",
            "allow_registered_transient_refinement",
            "std::cmp::max(risk, floor)",
        ):
            if fragment not in risk_text:
                failures.append(
                    f"trusted risk classification missing registered floor binding: {fragment}"
                )
    policy_review_path = root / POLICY_REVIEW_PATH
    if policy_review_path.is_file() and not policy_review_path.is_symlink():
        policy_review_text = policy_review_path.read_text(encoding="utf-8")
        if "review_plan_with_classification" not in policy_review_text:
            failures.append(
                "trusted policy review missing explicit risk-classification review path"
            )
    transient_path = root / TRANSIENT_EFFECT_PATH
    if transient_path.is_file() and not transient_path.is_symlink():
        transient_text = transient_path.read_text(encoding="utf-8")
        policy_review_index = transient_text.find("let review = review_plan_with_classification")
        no_change_success_index = transient_text.find(
            "TransientEffectAuditDisposition::NoChange"
        )
        if (
            policy_review_index < 0
            or no_change_success_index < 0
            or policy_review_index > no_change_success_index
        ):
            failures.append(
                "transient no-change success must remain downstream of trusted policy review"
            )
        audit_record_start = transient_text.find("pub struct TransientEffectAuditRecord")
        audit_record_end = transient_text.find("\n}\n", audit_record_start)
        if audit_record_start < 0 or audit_record_end < 0:
            failures.append("transient audit record shape is missing")
        else:
            audit_record_text = transient_text[audit_record_start:audit_record_end]
            if "pub detail:" in audit_record_text:
                failures.append(
                    "transient audit record must not persist arbitrary diagnostic text"
                )
        audit_reservation_index = transient_text.find(".reserve_attempt(&reservation)")
        executor_dispatch_index = transient_text.find("self.executor.execute(&effect)")
        if (
            audit_reservation_index < 0
            or executor_dispatch_index < 0
            or audit_reservation_index > executor_dispatch_index
        ):
            failures.append(
                "transient executor dispatch must remain downstream of durable audit reservation"
            )
        for fragment in (
            "pub struct TransientEffectControl",
            "pub trait TransientEffectExecutor",
            "pub trait TransientEffectAuditSink",
            ".authority_candidate(",
            ".resolve_external_with_requested_state(",
            "review_plan_with_classification",
            "PolicyDecision::Allow",
            "semantics.risk() > RiskClass::UserState",
            ".observe(&observation_request)",
            "FreshnessState::Current",
            "dispatch_started_unix_ms",
            "post_effect.observation.observed_at_unix_ms <= dispatch_started_unix_ms",
            "PostEffectEvidenceNotAfterDispatch",
            "PostEffectEvidenceReused",
            "PostEffectBindingMismatch",
            ".verify_post_effect(&effect, &post_effect.observation)",
            "TransientEffectAuditFailureCode::PostEffectBindingMismatch",
            "TransientEffectAuditDisposition::Verified",
            "requested_desired_state",
            "canonical_plan_sha256",
            "requested_postcondition_sha256",
            "pub enum TransientEffectAuditFailureCode",
            "TransientEffectAuditDisposition::AttemptReserved",
            "fn reserve_attempt(",
            "fn record_terminal(",
            "audit_attempt_sha256",
            "pub audit_attempt_sha256: String",
            "pub policy_id: PolicyId",
            "pub policy_revision_id: PolicyRevisionId",
            "pub policy_subject_risk: RiskClass",
            "pub risk_classification_revision: String",
            "pub risk_rule_ids: Vec<String>",
            "pub failure_code: Option<TransientEffectAuditFailureCode>",
            "risk_classification_audit_provenance",
            "provider: context.plan.provider.clone()",
            "principal: context.principal.as_str().to_owned()",
        ):
            if fragment not in transient_text:
                failures.append(
                    f"transient effect Control lifecycle missing required fragment: {fragment}"
                )
    core_text = core_path.read_text(encoding="utf-8") if core_path.is_file() and not core_path.is_symlink() else ""
    if "requires_plan_bound_external_authorization" not in core_text:
        failures.append("linura_core::OperationClass missing plan-bound external authorization invariant")

    session_dbus = root / SESSION_DBUS_PATH
    if session_dbus.is_file() and not session_dbus.is_symlink():
        session_dbus_text = session_dbus.read_text(encoding="utf-8")
        for fragment in (
            'SESSION_CONTRACT_ID: &str = "dbus.org.linura.Session1"',
            "pub trait Session1Handler",
            "async fn set_audio_output_volume(",
            ".set_audio_output_volume(context, request)",
            "session_service_uid(connection).await?",
            "require_same_session_uid(caller.uid, service_uid)?",
        ):
            if fragment not in session_dbus_text:
                failures.append(
                    f"Session1 transport missing required transient-effect fragment: {fragment}"
                )
        for forbidden in ("Command::new", "/usr/bin/wpctl", "PolicyDecision", "OperationClass"):
            if forbidden in session_dbus_text:
                failures.append(
                    f"Session1 transport must not own effect authority/execution: {forbidden}"
                )

    session_runtime = root / SESSION_RUNTIME_PATH
    if session_runtime.is_file() and not session_runtime.is_symlink():
        session_runtime_text = session_runtime.read_text(encoding="utf-8")
        for fragment in (
            "TransientEffectControl::new(",
            "effect.pre_effect_observation()",
            "expected_sink_identity(effect.pre_effect_observation(), effect.resource(), node_id)?",
            "fn verify_post_effect(",
            "verify_same_sink_identity(\n            effect.pre_effect_observation(),\n            post_effect,\n            effect.resource(),\n            node_id,\n        )",
            "verify_packaged_session_audio_helper()",
            "WIREPLUMBER_EXECUTABLE_PATH",
            "TRUSTED_SESSION_AUDIO_HELPER",
            "memfd_create(",
            "fcntl_add_seals(",
            '.arg("/dev/fd/0")',
            ".stdin(Stdio::from(trusted_helper))",
            ".env_clear()",
            "volume_percent > 100",
            "pipewire_output_node_id(effect.resource())",
            "observation.authority != ObservationAuthority::NativeApi",
        ):
            if fragment not in session_runtime_text:
                failures.append(
                    f"PipeWire session-volume runtime missing hardening fragment: {fragment}"
                )
        session_runtime_production_text = session_runtime_text.split("#[cfg(test)]", 1)[0]
        default_alias_dispatch = (
            '"audio:session:default-output"' in session_runtime_production_text
        )
        for forbidden in (
            '"/usr/bin/wpctl"',
            '"--limit"',
            "revalidate_identity(",
            ".arg(LINURA_SESSION_AUDIO_HELPER_PATH)",
        ):
            if forbidden in session_runtime_production_text:
                failures.append(
                    f"PipeWire session-volume runtime retains obsolete split wpctl authority: {forbidden}"
                )
        if default_alias_dispatch:
            failures.append(
                "PipeWire session-volume runtime must not accept the moving default-output alias"
            )

    session_audit = root / SESSION_AUDIT_PATH
    if session_audit.is_file() and not session_audit.is_symlink():
        session_audit_text = session_audit.read_text(encoding="utf-8")
        session_audit_production_text = session_audit_text.split("#[cfg(test)]", 1)[0]
        for fragment in (
            "impl TransientEffectAuditSink for SqliteTransientAudit",
            "fn reserve_attempt(",
            "fn record_terminal(",
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "verify_effective_sqlite_configuration(&connection)?",
            "fn verify_effective_sqlite_configuration(",
            '.eq_ignore_ascii_case("wal")',
            "SQLITE_SYNCHRONOUS_FULL",
            "TransactionBehavior::Immediate",
            "MAX_AUDIT_RECORDS",
            "MAX_DATABASE_BYTES",
            "metadata.nlink() != 1",
            "validate_exact_schema(&connection)?",
            "EXPECTED_AUDIT_COLUMNS",
            "PRAGMA max_page_count =",
            "PRAGMA journal_size_limit =",
            "checkpoint_and_validate_wal(&self.connection, &self.database_path)",
            "fn checkpoint_and_validate_wal(",
            'query_row("PRAGMA wal_checkpoint(TRUNCATE)"',
            "fn validate_wal_sidecar(",
            "metadata.len() > MAX_WAL_BYTES",
            "max_wal_frames",
            "PRAGMA wal_autocheckpoint = {max_wal_frames}",
            "configured_wal_autocheckpoint",
            "validate_wal_sidecar(path)?",
            "terminal audit has no durable attempt reservation",
        ):
            if fragment not in session_audit_production_text:
                failures.append(
                    f"transient session audit missing durability fragment: {fragment}"
                )


    arch_profile = root / ARCH_PROFILE_PATH
    if arch_profile.is_file() and not arch_profile.is_symlink():
        arch_profile_text = arch_profile.read_text(encoding="utf-8")
        helper_permission = (
            '["/usr/lib/linura/linura-session-audio.lua"]="0:0:0644"'
        )
        if helper_permission not in arch_profile_text:
            failures.append(
                "Arch workstation image must pin the trusted WirePlumber helper to root:root 0644"
            )

    helper = root / SESSION_AUDIO_HELPER_PATH
    if helper.is_file() and not helper.is_symlink():
        helper_text = helper.read_text(encoding="utf-8")
        required_helper_fragments = (
            "local raw_args = ...",
            "raw_args:parse(2)",
            "pcall(function()",
            'Constraint { "media.class", "equals", "Audio/Sink", type = "pw-global" }',
            'local properties = node["global-properties"]',
            'properties["object.serial"] == args.object_serial',
            'properties["node.name"] == args.node_name',
            'properties["media.class"] == "Audio/Sink"',
            'bound_id == args.node_id',
            'mixer:call("set-volume", matched_id, args.volume_percent / 100.0)',
            'mixer["scale"] = "cubic"',
            'sinks:connect("installed"',
            'sinks:activate()',
        )
        for fragment in required_helper_fragments:
            if fragment not in helper_text:
                failures.append(
                    f"WirePlumber session-audio helper missing identity-bound fragment: {fragment}"
                )
        identity_indices = [
            helper_text.find('bound_id == args.node_id'),
            helper_text.find('local properties = node["global-properties"]'),
            helper_text.find('properties["object.serial"] == args.object_serial'),
            helper_text.find('properties["node.name"] == args.node_name'),
        ]
        mutation_index = helper_text.find(
            'mixer:call("set-volume", matched_id, args.volume_percent / 100.0)'
        )
        if (
            any(index < 0 for index in identity_indices)
            or mutation_index < 0
            or any(index > mutation_index for index in identity_indices)
        ):
            failures.append(
                "WirePlumber session-audio mutation must remain downstream of exact object identity resolution"
            )
        if "local properties = node.properties" in helper_text:
            failures.append(
                "WirePlumber session-audio helper must bind identity from immutable PipeWire global properties"
            )
        for forbidden in ("os.execute", "io.", "/usr/bin/wpctl", "load(", "loadstring", "dofile"):
            if forbidden in helper_text:
                failures.append(
                    f"WirePlumber session-audio helper contains forbidden execution surface: {forbidden}"
                )

    linux_observation = root / LINUX_OBSERVATION_PATH
    if linux_observation.is_file() and not linux_observation.is_symlink():
        linux_observation_text = linux_observation.read_text(encoding="utf-8")
        for fragment in (
            'WIREPLUMBER_EXECUTABLE_PATH: &str = "/usr/bin/wpexec"',
            'LINURA_SESSION_AUDIO_HELPER_PATH',
            "parse_wireplumber_sink_snapshot",
            "verify_packaged_session_audio_helper",
            "open_file_descriptor(",
            "OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK",
            "Mode::empty()",
            ".env_clear()",
        ):
            if fragment not in linux_observation_text:
                failures.append(
                    f"PipeWire observer missing trusted WirePlumber helper fragment: {fragment}"
                )
        if "/usr/bin/wpctl" in linux_observation_text:
            failures.append(
                "PipeWire observer must not depend on the wpctl command surface"
            )
        if "String::from_utf8_lossy(&stderr)" in linux_observation_text:
            failures.append(
                "PipeWire observer must not expose raw WirePlumber stderr through provider diagnostics"
            )

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
