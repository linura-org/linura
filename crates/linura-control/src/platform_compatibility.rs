use linura_hardware::platform_profile::{
    PlatformEvidenceGap, PlatformFactAssessment, PlatformProfileCandidateContract,
    PlatformProfileCompatibility, PlatformProfileError,
};
use linura_observation::ObservationEnvelope;

/// Control-owned semantic aggregation of canonical platform observations.
///
/// Concrete Linux adapters remain outside `linura-control`. Composition roots
/// schedule narrow probes and pass canonical envelopes inward; Control owns
/// capability de-duplication, cross-fact aggregation, mismatch precedence and
/// the final candidate compatibility outcome.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCompatibilityControl;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformCompatibilityError {
    InvalidContract(PlatformProfileError),
    DuplicateObservationCapability(&'static str),
}

impl From<PlatformProfileError> for PlatformCompatibilityError {
    fn from(value: PlatformProfileError) -> Self {
        Self::InvalidContract(value)
    }
}

impl PlatformCompatibilityControl {
    pub fn assess(
        contract: PlatformProfileCandidateContract,
        observations: &[ObservationEnvelope],
        now_unix_ms: u64,
    ) -> Result<PlatformProfileCompatibility, PlatformCompatibilityError> {
        contract.validate()?;
        let mut mismatches = Vec::new();
        let mut gaps = Vec::new();

        for required in contract.required_facts() {
            let mut candidates = observations
                .iter()
                .filter(|item| item.capability.as_str() == required.capability());
            let Some(observation) = candidates.next() else {
                gaps.push(PlatformEvidenceGap {
                    key: required.key(),
                    reason: "required canonical observation was not provided".to_owned(),
                });
                continue;
            };
            if candidates.next().is_some() {
                return Err(PlatformCompatibilityError::DuplicateObservationCapability(
                    required.capability(),
                ));
            }

            match required.assess_observation(observation, now_unix_ms) {
                PlatformFactAssessment::Match => {}
                PlatformFactAssessment::KnownMismatch(mismatch) => mismatches.push(mismatch),
                PlatformFactAssessment::InsufficientEvidence(gap) => gaps.push(gap),
            }
        }

        if !mismatches.is_empty() {
            return Ok(PlatformProfileCompatibility::KnownMismatch {
                profile_id: contract.profile_id(),
                mismatches,
                gaps,
            });
        }
        if !gaps.is_empty() {
            return Ok(PlatformProfileCompatibility::InsufficientEvidence {
                profile_id: contract.profile_id(),
                gaps,
            });
        }
        Ok(PlatformProfileCompatibility::ExactCandidateMatch {
            profile_id: contract.profile_id(),
        })
    }

    pub fn assess_v010_arch_hyprland_v1(
        observations: &[ObservationEnvelope],
        now_unix_ms: u64,
    ) -> Result<PlatformProfileCompatibility, PlatformCompatibilityError> {
        Self::assess(
            PlatformProfileCandidateContract::v010_arch_hyprland_v1(),
            observations,
            now_unix_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_core::{CapabilityId, ProviderId, ResourceId};
    use linura_hardware::platform_profile::{
        PlatformFactKey, PlatformProfileCandidateContract, PlatformProfileCompatibility,
    };
    use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

    use super::*;

    fn fixture_observations() -> Vec<ObservationEnvelope> {
        PlatformProfileCandidateContract::v010_arch_hyprland_v1()
            .required_facts()
            .iter()
            .enumerate()
            .map(|(index, fact)| {
                let (provider, identity) = match fact.key() {
                    PlatformFactKey::Provider(_) => (fact.expected(), None),
                    _ => ("linux-platform", Some(fact.expected())),
                };
                let mut attributes = BTreeMap::from([(
                    "source".into(),
                    ObservedValue::Text("control-aggregation-fixture".into()),
                )]);
                if let Some(identity) = identity {
                    attributes.insert("identity".into(), ObservedValue::Text(identity.to_owned()));
                }
                ObservationEnvelope {
                    provider: ProviderId::new(provider)
                        .unwrap_or_else(|error| unreachable!("{error}")),
                    resource: ResourceId::new(fact.resource())
                        .unwrap_or_else(|error| unreachable!("{error}")),
                    capability: CapabilityId::new(fact.capability())
                        .unwrap_or_else(|error| unreachable!("{error}")),
                    authority: fact.authority(),
                    observed_at_unix_ms: 1_000,
                    valid_for_ms: 2_000,
                    sequence: u64::try_from(index + 1)
                        .unwrap_or_else(|_| unreachable!("fixture index fits u64")),
                    attributes,
                }
            })
            .collect()
    }

    #[test]
    fn control_owns_cross_fact_compatibility_aggregation() {
        let result = PlatformCompatibilityControl::assess_v010_arch_hyprland_v1(
            &fixture_observations(),
            1_500,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::ExactCandidateMatch { .. }
        ));
        assert!(!result.release_qualified());
    }

    #[test]
    fn missing_probe_evidence_remains_insufficient() {
        let mut observations = fixture_observations();
        observations.pop();
        let result =
            PlatformCompatibilityControl::assess_v010_arch_hyprland_v1(&observations, 1_500)
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::InsufficientEvidence { .. }
        ));
    }

    #[test]
    fn known_mismatch_dominates_other_evidence_gaps() {
        let mut observations = fixture_observations();
        observations.retain(|item| item.capability.as_str() != "platform.compositor.observe");
        let network = observations
            .iter_mut()
            .find(|item| item.capability.as_str() == "platform.provider.network.observe")
            .unwrap_or_else(|| unreachable!("network fixture missing"));
        network.provider =
            ProviderId::new("systemd-networkd").unwrap_or_else(|error| unreachable!("{error}"));

        let result =
            PlatformCompatibilityControl::assess_v010_arch_hyprland_v1(&observations, 1_500)
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::KnownMismatch { .. }
        ));
    }

    #[test]
    fn duplicate_capability_evidence_fails_closed() {
        let mut observations = fixture_observations();
        observations.push(observations[0].clone());
        assert_eq!(
            PlatformCompatibilityControl::assess_v010_arch_hyprland_v1(&observations, 1_500),
            Err(PlatformCompatibilityError::DuplicateObservationCapability(
                "platform.distribution.observe"
            ))
        );
    }
}
