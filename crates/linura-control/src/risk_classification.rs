use linura_core::RiskClass;
use linura_planner::{PlanStatus, ReconciliationPlan};

pub(crate) const BASELINE_RISK_POLICY_REVISION: &str = "risk-policy:v0.3:1";
pub(crate) const REGISTERED_OPERATION_RISK_POLICY_REVISION: &str =
    "risk-policy:v0.10:registered-operation-floor";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RiskRule {
    id: &'static str,
    provider: &'static str,
    capability: &'static str,
    resource_prefix: &'static str,
    change_keys: &'static [&'static str],
    risk: RiskClass,
}

impl RiskRule {
    fn matches(self, plan: &ReconciliationPlan) -> bool {
        plan.provider.as_str() == self.provider
            && plan.observation_capability.as_str() == self.capability
            && plan.resource.as_str().starts_with(self.resource_prefix)
            && !plan.changes.is_empty()
            && plan
                .changes
                .iter()
                .all(|change| self.change_keys.contains(&change.key.as_str()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RiskClassification {
    NotApplicable {
        risk: RiskClass,
    },
    Classified {
        risk: RiskClass,
        revision: &'static str,
        rule_ids: Vec<&'static str>,
    },
    Unclassified {
        revision: &'static str,
        reason: String,
    },
    DowngradeRejected {
        revision: &'static str,
        floor: RiskClass,
        classified: RiskClass,
        rule_ids: Vec<&'static str>,
    },
}

#[derive(Clone, Debug)]
struct RiskPolicy {
    revision: &'static str,
    rules: Vec<RiskRule>,
}

impl RiskPolicy {
    fn baseline() -> Self {
        // v0.3 has no supported mutation path, so the initial trusted risk policy
        // is intentionally narrow and conservative. Starting/stopping any systemd
        // unit can change service exposure, privilege boundaries or availability;
        // classify that route as security-sensitive rather than guessing that an
        // arbitrary unit is an ordinary mutation. Other mutation shapes fail
        // closed until a reviewed typed rule is introduced.
        Self {
            revision: BASELINE_RISK_POLICY_REVISION,
            rules: vec![RiskRule {
                id: "systemd.unit.active-state.security-sensitive",
                provider: "systemd",
                capability: "systemd.unit.observe",
                resource_prefix: "systemd:unit:",
                change_keys: &["active_state"],
                risk: RiskClass::SecuritySensitive,
            }],
        }
    }

    fn classify(&self, plan: &ReconciliationPlan) -> RiskClassification {
        if plan.status != PlanStatus::ChangeProposed || plan.changes.is_empty() {
            return RiskClassification::NotApplicable {
                risk: plan.prospective_risk,
            };
        }

        let mut matched: Vec<RiskRule> = self
            .rules
            .iter()
            .copied()
            .filter(|rule| rule.matches(plan))
            .collect();
        matched.sort_by_key(|rule| rule.id);

        if matched.is_empty() {
            return RiskClassification::Unclassified {
                revision: self.revision,
                reason: format!(
                    "no trusted risk rule covers provider={} resource={} capability={} change_keys={:?}",
                    plan.provider.as_str(),
                    plan.resource.as_str(),
                    plan.observation_capability.as_str(),
                    plan.changes
                        .iter()
                        .map(|change| change.key.as_str())
                        .collect::<Vec<_>>()
                ),
            };
        }

        let classified = matched
            .iter()
            .map(|rule| rule.risk)
            .max()
            .unwrap_or(plan.prospective_risk);
        let rule_ids = matched.iter().map(|rule| rule.id).collect::<Vec<_>>();

        if classified < plan.prospective_risk {
            return RiskClassification::DowngradeRejected {
                revision: self.revision,
                floor: plan.prospective_risk,
                classified,
                rule_ids,
            };
        }

        RiskClassification::Classified {
            risk: classified,
            revision: self.revision,
            rule_ids,
        }
    }
}

pub(crate) fn classify_plan_risk(plan: &ReconciliationPlan) -> RiskClassification {
    RiskPolicy::baseline().classify(plan)
}

pub(crate) fn classify_plan_risk_with_floor(
    plan: &ReconciliationPlan,
    floor: RiskClass,
    floor_rule_id: &'static str,
) -> RiskClassification {
    match classify_plan_risk(plan) {
        RiskClassification::Classified {
            risk, mut rule_ids, ..
        } => {
            rule_ids.push(floor_rule_id);
            rule_ids.sort_unstable();
            rule_ids.dedup();
            RiskClassification::Classified {
                risk: std::cmp::max(risk, floor),
                revision: REGISTERED_OPERATION_RISK_POLICY_REVISION,
                rule_ids,
            }
        }
        RiskClassification::NotApplicable { risk } => RiskClassification::NotApplicable {
            risk: std::cmp::max(risk, floor),
        },
        other @ (RiskClassification::Unclassified { .. }
        | RiskClassification::DowngradeRejected { .. }) => other,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_core::{
        Actor, ActorId, ActorKind, CapabilityId, IntentId, ProviderId, RequestId, ResourceId,
        SemanticReason,
    };
    use linura_planner::{
        DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
    };

    use super::*;

    fn canonical_plan(resource: &str) -> ReconciliationPlan {
        let provider = ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new(resource).unwrap_or_else(|error| unreachable!("{error}"));
        let capability = CapabilityId::new("systemd.unit.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "manage test unit".into(),
                intent_ids: vec![
                    IntentId::new("intent:risk").unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        };
        let observation = PlanningObservation {
            provider,
            resource,
            observation_capability: capability,
            authority: "authoritative".into(),
            evidence_id: "evidence:risk".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("active_state".into(), "inactive".into())]),
        };
        DeterministicPlanner
            .plan_resource(
                RequestId::new("request:risk").unwrap_or_else(|error| unreachable!("{error}")),
                Actor {
                    id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                desired,
                &observation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn baseline_systemd_active_state_is_security_sensitive() {
        let plan = canonical_plan("systemd:unit:test.service");
        let classification = classify_plan_risk(&plan);
        assert!(matches!(
            classification,
            RiskClassification::Classified {
                risk: RiskClass::SecuritySensitive,
                ..
            }
        ));
    }

    #[test]
    fn registered_operation_floor_is_bound_into_risk_provenance() {
        let plan = canonical_plan("systemd:unit:test.service");
        let classification = classify_plan_risk_with_floor(
            &plan,
            RiskClass::Destructive,
            "operation-registry:test-floor",
        );
        assert_eq!(
            classification,
            RiskClassification::Classified {
                risk: RiskClass::Destructive,
                revision: REGISTERED_OPERATION_RISK_POLICY_REVISION,
                rule_ids: vec![
                    "operation-registry:test-floor",
                    "systemd.unit.active-state.security-sensitive",
                ],
            }
        );
    }

    #[test]
    fn unmatched_change_shape_fails_closed() {
        let mut plan = canonical_plan("systemd:unit:test.service");
        plan.changes[0].key = "fragment_path".into();
        let classification = classify_plan_risk(&plan);
        assert!(matches!(
            classification,
            RiskClassification::Unclassified { .. }
        ));
    }

    #[test]
    fn lower_rule_cannot_downgrade_planner_floor() {
        let plan = canonical_plan("systemd:unit:test.service");
        let policy = RiskPolicy {
            revision: "risk-policy:test:downgrade",
            rules: vec![RiskRule {
                id: "unsafe-downgrade",
                provider: "systemd",
                capability: "systemd.unit.observe",
                resource_prefix: "systemd:unit:",
                change_keys: &["active_state"],
                risk: RiskClass::UserState,
            }],
        };
        assert!(matches!(
            policy.classify(&plan),
            RiskClassification::DowngradeRejected {
                floor: RiskClass::SystemMutation,
                classified: RiskClass::UserState,
                ..
            }
        ));
    }

    #[test]
    fn canonical_plan_can_be_classified_destructive_by_trusted_rule() {
        let plan = canonical_plan("systemd:unit:dangerous.service");
        let policy = RiskPolicy {
            revision: "risk-policy:test:destructive",
            rules: vec![RiskRule {
                id: "test.destructive",
                provider: "systemd",
                capability: "systemd.unit.observe",
                resource_prefix: "systemd:unit:dangerous.service",
                change_keys: &["active_state"],
                risk: RiskClass::Destructive,
            }],
        };
        assert!(matches!(
            policy.classify(&plan),
            RiskClassification::Classified {
                risk: RiskClass::Destructive,
                ..
            }
        ));
    }

    #[test]
    fn overlapping_rules_choose_the_highest_risk_deterministically() {
        let plan = canonical_plan("systemd:unit:critical.service");
        let policy = RiskPolicy {
            revision: "risk-policy:test:overlap",
            rules: vec![
                RiskRule {
                    id: "z-broad",
                    provider: "systemd",
                    capability: "systemd.unit.observe",
                    resource_prefix: "systemd:unit:",
                    change_keys: &["active_state"],
                    risk: RiskClass::SystemMutation,
                },
                RiskRule {
                    id: "a-critical",
                    provider: "systemd",
                    capability: "systemd.unit.observe",
                    resource_prefix: "systemd:unit:critical.service",
                    change_keys: &["active_state"],
                    risk: RiskClass::Destructive,
                },
            ],
        };
        assert_eq!(
            policy.classify(&plan),
            RiskClassification::Classified {
                risk: RiskClass::Destructive,
                revision: "risk-policy:test:overlap",
                rule_ids: vec!["a-critical", "z-broad"],
            }
        );
    }
}
