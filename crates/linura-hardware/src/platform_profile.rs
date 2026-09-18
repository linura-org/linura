use std::collections::BTreeSet;

use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

use super::MachineClass;

pub const ARCH_HYPRLAND_V1_PROFILE_ID: &str = "arch-hyprland-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlatformProviderRole {
    Network,
    Bluetooth,
    Audio,
    Storage,
    Authorization,
    Filesystem,
    Snapshots,
}

impl PlatformProviderRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Bluetooth => "bluetooth",
            Self::Audio => "audio",
            Self::Storage => "storage",
            Self::Authorization => "authorization",
            Self::Filesystem => "filesystem",
            Self::Snapshots => "snapshots",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlatformFactKey {
    Distribution,
    Architecture,
    InitSystem,
    Session,
    Compositor,
    Provider(PlatformProviderRole),
}

impl PlatformFactKey {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Distribution => "distribution",
            Self::Architecture => "architecture",
            Self::InitSystem => "init_system",
            Self::Session => "session",
            Self::Compositor => "compositor",
            Self::Provider(role) => match role {
                PlatformProviderRole::Network => "provider.network",
                PlatformProviderRole::Bluetooth => "provider.bluetooth",
                PlatformProviderRole::Audio => "provider.audio",
                PlatformProviderRole::Storage => "provider.storage",
                PlatformProviderRole::Authorization => "provider.authorization",
                PlatformProviderRole::Filesystem => "provider.filesystem",
                PlatformProviderRole::Snapshots => "provider.snapshots",
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlatformFactValueSource {
    Attribute(&'static str),
    ProviderIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredPlatformFact {
    key: PlatformFactKey,
    capability: &'static str,
    evidence_provider: Option<&'static str>,
    source: PlatformFactValueSource,
    expected: &'static str,
}

impl RequiredPlatformFact {
    const fn attribute(
        key: PlatformFactKey,
        capability: &'static str,
        evidence_provider: &'static str,
        expected: &'static str,
    ) -> Self {
        Self {
            key,
            capability,
            evidence_provider: Some(evidence_provider),
            source: PlatformFactValueSource::Attribute("identity"),
            expected,
        }
    }

    const fn provider(
        role: PlatformProviderRole,
        capability: &'static str,
        expected: &'static str,
    ) -> Self {
        Self {
            key: PlatformFactKey::Provider(role),
            capability,
            evidence_provider: None,
            source: PlatformFactValueSource::ProviderIdentity,
            expected,
        }
    }

    #[must_use]
    pub const fn key(self) -> PlatformFactKey {
        self.key
    }

    #[must_use]
    pub const fn capability(self) -> &'static str {
        self.capability
    }

    #[must_use]
    pub const fn expected(self) -> &'static str {
        self.expected
    }

    /// Assess exactly one canonical observation against this one required fact.
    ///
    /// Cross-fact/provider aggregation is intentionally owned by Linura Control.
    #[must_use]
    pub fn assess_observation(
        self,
        observation: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> PlatformFactAssessment {
        if observation
            .validate(
                &observation.provider,
                &observation.resource,
                &observation.capability,
            )
            .is_err()
            || observation.require_current(now_unix_ms).is_err()
        {
            return PlatformFactAssessment::InsufficientEvidence(PlatformEvidenceGap {
                key: self.key,
                reason: "canonical observation is invalid, stale, or future-dated".to_owned(),
            });
        }
        if observation.capability.as_str() != self.capability {
            return PlatformFactAssessment::InsufficientEvidence(PlatformEvidenceGap {
                key: self.key,
                reason: "canonical observation has the wrong capability".to_owned(),
            });
        }
        if self
            .evidence_provider
            .is_some_and(|provider| observation.provider.as_str() != provider)
        {
            return PlatformFactAssessment::InsufficientEvidence(PlatformEvidenceGap {
                key: self.key,
                reason: "canonical observation came from an unexpected provider".to_owned(),
            });
        }

        let observed = match self.source {
            PlatformFactValueSource::ProviderIdentity => observation.provider.as_str().to_owned(),
            PlatformFactValueSource::Attribute(attribute) => {
                let Some(ObservedValue::Text(value)) = observation.attributes.get(attribute) else {
                    return PlatformFactAssessment::InsufficientEvidence(PlatformEvidenceGap {
                        key: self.key,
                        reason: "canonical observation omitted the required text attribute"
                            .to_owned(),
                    });
                };
                value.clone()
            }
        };

        if observed == self.expected {
            PlatformFactAssessment::Match
        } else {
            PlatformFactAssessment::KnownMismatch(PlatformFactMismatch {
                key: self.key,
                expected: self.expected,
                observed,
                authority: observation.authority,
                evidence_id: observation.evidence_id(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformProfileCandidateContract {
    profile_id: &'static str,
    milestone: &'static str,
    machine_class: MachineClass,
    required_facts: &'static [RequiredPlatformFact],
}

impl PlatformProfileCandidateContract {
    #[must_use]
    pub const fn new(
        profile_id: &'static str,
        milestone: &'static str,
        machine_class: MachineClass,
        required_facts: &'static [RequiredPlatformFact],
    ) -> Self {
        Self {
            profile_id,
            milestone,
            machine_class,
            required_facts,
        }
    }

    #[must_use]
    pub const fn v010_arch_hyprland_v1() -> Self {
        Self::new(
            ARCH_HYPRLAND_V1_PROFILE_ID,
            "v0.10.0",
            MachineClass::Workstation,
            &ARCH_HYPRLAND_V1_REQUIRED_FACTS,
        )
    }

    #[must_use]
    pub const fn profile_id(self) -> &'static str {
        self.profile_id
    }

    #[must_use]
    pub const fn milestone(self) -> &'static str {
        self.milestone
    }

    #[must_use]
    pub const fn machine_class(self) -> MachineClass {
        self.machine_class
    }

    #[must_use]
    pub const fn required_facts(self) -> &'static [RequiredPlatformFact] {
        self.required_facts
    }

    pub fn validate(self) -> Result<(), PlatformProfileError> {
        validate_contract_literal("profile_id", self.profile_id)?;
        validate_contract_literal("milestone", self.milestone)?;
        if self.required_facts.is_empty() {
            return Err(PlatformProfileError::InvalidContractField("required_facts"));
        }
        let mut keys = BTreeSet::new();
        let mut capabilities = BTreeSet::new();
        for fact in self.required_facts {
            validate_contract_literal(fact.key.as_str(), fact.expected)?;
            validate_contract_literal("observation capability", fact.capability)?;
            if let Some(provider) = fact.evidence_provider {
                validate_contract_literal("evidence provider", provider)?;
            }
            if !keys.insert(fact.key) {
                return Err(PlatformProfileError::DuplicateRequiredFact(fact.key));
            }
            if !capabilities.insert(fact.capability) {
                return Err(PlatformProfileError::DuplicateRequiredCapability(
                    fact.capability,
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformFactAssessment {
    Match,
    KnownMismatch(PlatformFactMismatch),
    InsufficientEvidence(PlatformEvidenceGap),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformFactMismatch {
    pub key: PlatformFactKey,
    pub expected: &'static str,
    pub observed: String,
    pub authority: ObservationAuthority,
    pub evidence_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformEvidenceGap {
    pub key: PlatformFactKey,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformProfileCompatibility {
    ExactCandidateMatch {
        profile_id: &'static str,
    },
    KnownMismatch {
        profile_id: &'static str,
        mismatches: Vec<PlatformFactMismatch>,
        gaps: Vec<PlatformEvidenceGap>,
    },
    InsufficientEvidence {
        profile_id: &'static str,
        gaps: Vec<PlatformEvidenceGap>,
    },
}

impl PlatformProfileCompatibility {
    #[must_use]
    pub const fn profile_id(&self) -> &'static str {
        match self {
            Self::ExactCandidateMatch { profile_id }
            | Self::KnownMismatch { profile_id, .. }
            | Self::InsufficientEvidence { profile_id, .. } => profile_id,
        }
    }

    #[must_use]
    pub const fn is_exact_candidate_match(&self) -> bool {
        matches!(self, Self::ExactCandidateMatch { .. })
    }

    /// Candidate compatibility is deliberately not release qualification.
    /// Protected release evidence and post-release closure own that transition.
    #[must_use]
    pub const fn release_qualified(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformProfileError {
    InvalidContractField(&'static str),
    DuplicateRequiredFact(PlatformFactKey),
    DuplicateRequiredCapability(&'static str),
}

pub const PLATFORM_DISTRIBUTION_CAPABILITY: &str = "platform.distribution.observe";
pub const PLATFORM_ARCHITECTURE_CAPABILITY: &str = "platform.architecture.observe";
pub const PLATFORM_INIT_CAPABILITY: &str = "platform.init-system.observe";
pub const PLATFORM_SESSION_CAPABILITY: &str = "platform.session.observe";
pub const PLATFORM_COMPOSITOR_CAPABILITY: &str = "platform.compositor.observe";
pub const PLATFORM_NETWORK_PROVIDER_CAPABILITY: &str = "platform.provider.network.observe";
pub const PLATFORM_BLUETOOTH_PROVIDER_CAPABILITY: &str = "platform.provider.bluetooth.observe";
pub const PLATFORM_AUDIO_PROVIDER_CAPABILITY: &str = "platform.provider.audio.observe";
pub const PLATFORM_STORAGE_PROVIDER_CAPABILITY: &str = "platform.provider.storage.observe";
pub const PLATFORM_AUTHORIZATION_PROVIDER_CAPABILITY: &str =
    "platform.provider.authorization.observe";
pub const PLATFORM_FILESYSTEM_PROVIDER_CAPABILITY: &str = "platform.provider.filesystem.observe";
pub const PLATFORM_SNAPSHOTS_PROVIDER_CAPABILITY: &str = "platform.provider.snapshots.observe";

const ARCH_HYPRLAND_V1_REQUIRED_FACTS: [RequiredPlatformFact; 12] = [
    RequiredPlatformFact::attribute(
        PlatformFactKey::Distribution,
        PLATFORM_DISTRIBUTION_CAPABILITY,
        "linux-platform",
        "arch",
    ),
    RequiredPlatformFact::attribute(
        PlatformFactKey::Architecture,
        PLATFORM_ARCHITECTURE_CAPABILITY,
        "linux-platform",
        "x86_64",
    ),
    RequiredPlatformFact::attribute(
        PlatformFactKey::InitSystem,
        PLATFORM_INIT_CAPABILITY,
        "linux-platform",
        "systemd",
    ),
    RequiredPlatformFact::attribute(
        PlatformFactKey::Session,
        PLATFORM_SESSION_CAPABILITY,
        "linux-platform",
        "wayland",
    ),
    RequiredPlatformFact::attribute(
        PlatformFactKey::Compositor,
        PLATFORM_COMPOSITOR_CAPABILITY,
        "linux-platform",
        "hyprland",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Network,
        PLATFORM_NETWORK_PROVIDER_CAPABILITY,
        "networkmanager",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Bluetooth,
        PLATFORM_BLUETOOTH_PROVIDER_CAPABILITY,
        "bluez",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Audio,
        PLATFORM_AUDIO_PROVIDER_CAPABILITY,
        "pipewire-wireplumber",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Storage,
        PLATFORM_STORAGE_PROVIDER_CAPABILITY,
        "udisks2",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Authorization,
        PLATFORM_AUTHORIZATION_PROVIDER_CAPABILITY,
        "polkit",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Filesystem,
        PLATFORM_FILESYSTEM_PROVIDER_CAPABILITY,
        "btrfs",
    ),
    RequiredPlatformFact::provider(
        PlatformProviderRole::Snapshots,
        PLATFORM_SNAPSHOTS_PROVIDER_CAPABILITY,
        "snapper",
    ),
];

fn validate_contract_literal(
    field: &'static str,
    value: &'static str,
) -> Result<(), PlatformProfileError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err(PlatformProfileError::InvalidContractField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_core::{CapabilityId, ProviderId, ResourceId};
    use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

    use super::*;

    const OBSERVED_AT: u64 = 1_000;
    const NOW: u64 = 1_500;

    fn envelope(
        provider: &str,
        resource: &str,
        capability: &str,
        authority: ObservationAuthority,
        identity: Option<&str>,
    ) -> ObservationEnvelope {
        let mut attributes = BTreeMap::from([(
            "source".into(),
            ObservedValue::Text("qualification-fixture".into()),
        )]);
        if let Some(identity) = identity {
            attributes.insert("identity".into(), ObservedValue::Text(identity.into()));
        }
        ObservationEnvelope {
            provider: ProviderId::new(provider).unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new(resource).unwrap_or_else(|error| unreachable!("{error}")),
            capability: CapabilityId::new(capability)
                .unwrap_or_else(|error| unreachable!("{error}")),
            authority,
            observed_at_unix_ms: OBSERVED_AT,
            valid_for_ms: 2_000,
            sequence: 1,
            attributes,
        }
    }

    #[test]
    fn v010_arch_profile_contract_is_exact_and_versionless() {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        assert_eq!(contract.validate(), Ok(()));
        assert_eq!(contract.profile_id(), ARCH_HYPRLAND_V1_PROFILE_ID);
        assert_eq!(contract.milestone(), "v0.10.0");
        assert_eq!(contract.machine_class(), MachineClass::Workstation);
        assert_eq!(contract.required_facts().len(), 12);
        assert!(
            contract
                .required_facts()
                .iter()
                .all(|fact| fact.key().as_str() != "distribution_version")
        );
    }

    fn required_fact(key: PlatformFactKey) -> RequiredPlatformFact {
        PlatformProfileCandidateContract::v010_arch_hyprland_v1()
            .required_facts()
            .iter()
            .copied()
            .find(|fact| fact.key() == key)
            .unwrap_or_else(|| unreachable!("required fact fixture missing"))
    }

    #[test]
    fn one_fact_matches_only_from_canonical_observation() {
        let fact = required_fact(PlatformFactKey::Distribution);
        let observation = envelope(
            "linux-platform",
            "platform:distribution",
            PLATFORM_DISTRIBUTION_CAPABILITY,
            ObservationAuthority::SyntheticTest,
            Some("arch"),
        );
        assert_eq!(
            fact.assess_observation(&observation, NOW),
            PlatformFactAssessment::Match
        );
    }

    #[test]
    fn one_fact_reports_known_mismatch() {
        let fact = required_fact(PlatformFactKey::Provider(PlatformProviderRole::Network));
        let observation = envelope(
            "systemd-networkd",
            "platform:provider:network",
            PLATFORM_NETWORK_PROVIDER_CAPABILITY,
            ObservationAuthority::SyntheticTest,
            None,
        );
        assert!(matches!(
            fact.assess_observation(&observation, NOW),
            PlatformFactAssessment::KnownMismatch(_)
        ));
    }

    #[test]
    fn stale_single_fact_evidence_is_insufficient() {
        let fact = required_fact(PlatformFactKey::Distribution);
        let observation = envelope(
            "linux-platform",
            "platform:distribution",
            PLATFORM_DISTRIBUTION_CAPABILITY,
            ObservationAuthority::SyntheticTest,
            Some("arch"),
        );
        assert!(matches!(
            fact.assess_observation(&observation, 10_000),
            PlatformFactAssessment::InsufficientEvidence(_)
        ));
    }

    #[test]
    fn unexpected_evidence_provider_is_insufficient() {
        let fact = required_fact(PlatformFactKey::Distribution);
        let observation = envelope(
            "untrusted-platform-source",
            "platform:distribution",
            PLATFORM_DISTRIBUTION_CAPABILITY,
            ObservationAuthority::SyntheticTest,
            Some("arch"),
        );
        assert!(matches!(
            fact.assess_observation(&observation, NOW),
            PlatformFactAssessment::InsufficientEvidence(_)
        ));
    }
}
