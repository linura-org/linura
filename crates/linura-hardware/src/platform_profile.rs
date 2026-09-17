use std::collections::{BTreeMap, BTreeSet};

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
pub enum PlatformObservationAuthority {
    NativeOsRelease,
    NativeArchitecture,
    NativeInit,
    NativeSession,
    NativeCompositor,
    NativeProviderApi,
    QualificationFixture,
}

impl PlatformObservationAuthority {
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::QualificationFixture)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformFactEvidence {
    Observed {
        value: String,
        authority: PlatformObservationAuthority,
    },
    Unavailable {
        reason: String,
    },
}

impl PlatformFactEvidence {
    pub fn observed(
        value: impl Into<String>,
        authority: PlatformObservationAuthority,
    ) -> Result<Self, PlatformProfileError> {
        Ok(Self::Observed {
            value: validate_platform_text("platform fact value", value.into(), 256)?,
            authority,
        })
    }

    pub fn unavailable(reason: impl Into<String>) -> Result<Self, PlatformProfileError> {
        Ok(Self::Unavailable {
            reason: validate_platform_text("platform evidence gap reason", reason.into(), 1024)?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformObservation {
    facts: BTreeMap<PlatformFactKey, PlatformFactEvidence>,
}

impl PlatformObservation {
    pub fn record_observed(
        &mut self,
        key: PlatformFactKey,
        value: impl Into<String>,
        authority: PlatformObservationAuthority,
    ) -> Result<(), PlatformProfileError> {
        self.record(key, PlatformFactEvidence::observed(value, authority)?)
    }

    pub fn record_unavailable(
        &mut self,
        key: PlatformFactKey,
        reason: impl Into<String>,
    ) -> Result<(), PlatformProfileError> {
        self.record(key, PlatformFactEvidence::unavailable(reason)?)
    }

    pub fn record(
        &mut self,
        key: PlatformFactKey,
        evidence: PlatformFactEvidence,
    ) -> Result<(), PlatformProfileError> {
        if self.facts.contains_key(&key) {
            return Err(PlatformProfileError::DuplicateObservationFact(key));
        }
        self.facts.insert(key, evidence);
        Ok(())
    }

    #[must_use]
    pub fn fact(&self, key: PlatformFactKey) -> Option<&PlatformFactEvidence> {
        self.facts.get(&key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredPlatformFact {
    key: PlatformFactKey,
    expected: &'static str,
}

impl RequiredPlatformFact {
    #[must_use]
    pub const fn new(key: PlatformFactKey, expected: &'static str) -> Self {
        Self { key, expected }
    }

    #[must_use]
    pub const fn key(self) -> PlatformFactKey {
        self.key
    }

    #[must_use]
    pub const fn expected(self) -> &'static str {
        self.expected
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
        let mut seen = BTreeSet::new();
        for fact in self.required_facts {
            validate_contract_literal(fact.key.as_str(), fact.expected)?;
            if !seen.insert(fact.key) {
                return Err(PlatformProfileError::DuplicateRequiredFact(fact.key));
            }
        }
        Ok(())
    }

    pub fn assess(
        self,
        observation: &PlatformObservation,
    ) -> Result<PlatformProfileCompatibility, PlatformProfileError> {
        self.validate()?;
        let mut mismatches = Vec::new();
        let mut gaps = Vec::new();

        for required in self.required_facts {
            match observation.fact(required.key) {
                Some(PlatformFactEvidence::Observed { value, authority }) => {
                    if value != required.expected {
                        mismatches.push(PlatformFactMismatch {
                            key: required.key,
                            expected: required.expected,
                            observed: value.clone(),
                            authority: *authority,
                        });
                    }
                }
                Some(PlatformFactEvidence::Unavailable { reason }) => {
                    gaps.push(PlatformEvidenceGap {
                        key: required.key,
                        reason: reason.clone(),
                    });
                }
                None => gaps.push(PlatformEvidenceGap {
                    key: required.key,
                    reason: "required fact was not observed".to_owned(),
                }),
            }
        }

        if !mismatches.is_empty() {
            return Ok(PlatformProfileCompatibility::KnownMismatch {
                profile_id: self.profile_id,
                mismatches,
                gaps,
            });
        }
        if !gaps.is_empty() {
            return Ok(PlatformProfileCompatibility::InsufficientEvidence {
                profile_id: self.profile_id,
                gaps,
            });
        }
        Ok(PlatformProfileCompatibility::ExactCandidateMatch {
            profile_id: self.profile_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformFactMismatch {
    pub key: PlatformFactKey,
    pub expected: &'static str,
    pub observed: String,
    pub authority: PlatformObservationAuthority,
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
    InvalidEvidenceField(&'static str),
    DuplicateRequiredFact(PlatformFactKey),
    DuplicateObservationFact(PlatformFactKey),
}

const ARCH_HYPRLAND_V1_REQUIRED_FACTS: [RequiredPlatformFact; 12] = [
    RequiredPlatformFact::new(PlatformFactKey::Distribution, "arch"),
    RequiredPlatformFact::new(PlatformFactKey::Architecture, "x86_64"),
    RequiredPlatformFact::new(PlatformFactKey::InitSystem, "systemd"),
    RequiredPlatformFact::new(PlatformFactKey::Session, "wayland"),
    RequiredPlatformFact::new(PlatformFactKey::Compositor, "hyprland"),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Network),
        "networkmanager",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Bluetooth),
        "bluez",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Audio),
        "pipewire-wireplumber",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Storage),
        "udisks2",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Authorization),
        "polkit",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Filesystem),
        "btrfs",
    ),
    RequiredPlatformFact::new(
        PlatformFactKey::Provider(PlatformProviderRole::Snapshots),
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

fn validate_platform_text(
    field: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, PlatformProfileError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len || trimmed.chars().any(char::is_control) {
        return Err(PlatformProfileError::InvalidEvidenceField(field));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority_for(key: PlatformFactKey) -> PlatformObservationAuthority {
        match key {
            PlatformFactKey::Distribution => PlatformObservationAuthority::NativeOsRelease,
            PlatformFactKey::Architecture => PlatformObservationAuthority::NativeArchitecture,
            PlatformFactKey::InitSystem => PlatformObservationAuthority::NativeInit,
            PlatformFactKey::Session => PlatformObservationAuthority::NativeSession,
            PlatformFactKey::Compositor => PlatformObservationAuthority::NativeCompositor,
            PlatformFactKey::Provider(_) => PlatformObservationAuthority::NativeProviderApi,
        }
    }

    fn exact_observation() -> PlatformObservation {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        let mut observation = PlatformObservation::default();
        for required in contract.required_facts() {
            observation
                .record_observed(
                    required.key(),
                    required.expected(),
                    authority_for(required.key()),
                )
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        }
        observation
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

    #[test]
    fn exact_candidate_match_is_not_release_qualification() {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        let result = contract
            .assess(&exact_observation())
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(result.is_exact_candidate_match());
        assert_eq!(result.profile_id(), ARCH_HYPRLAND_V1_PROFILE_ID);
        assert!(!result.release_qualified());
    }

    #[test]
    fn missing_session_evidence_is_insufficient_not_a_match() {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        let mut observation = PlatformObservation::default();
        for required in contract.required_facts() {
            if required.key() == PlatformFactKey::Session {
                observation
                    .record_unavailable(required.key(), "no authoritative Wayland session evidence")
                    .unwrap_or_else(|error| unreachable!("{error:?}"));
            } else {
                observation
                    .record_observed(
                        required.key(),
                        required.expected(),
                        authority_for(required.key()),
                    )
                    .unwrap_or_else(|error| unreachable!("{error:?}"));
            }
        }

        let result = contract
            .assess(&observation)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::InsufficientEvidence { .. }
        ));
        if let PlatformProfileCompatibility::InsufficientEvidence { gaps, .. } = result {
            assert_eq!(gaps.len(), 1);
            assert_eq!(gaps[0].key, PlatformFactKey::Session);
        }
    }

    #[test]
    fn known_distribution_mismatch_dominates_other_evidence_gaps() {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        let mut observation = PlatformObservation::default();
        observation
            .record_observed(
                PlatformFactKey::Distribution,
                "ubuntu",
                PlatformObservationAuthority::NativeOsRelease,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        let result = contract
            .assess(&observation)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::KnownMismatch { .. }
        ));
        if let PlatformProfileCompatibility::KnownMismatch {
            mismatches, gaps, ..
        } = result
        {
            assert_eq!(mismatches.len(), 1);
            assert_eq!(mismatches[0].key, PlatformFactKey::Distribution);
            assert_eq!(mismatches[0].expected, "arch");
            assert_eq!(mismatches[0].observed, "ubuntu");
            assert!(!gaps.is_empty());
        }
    }

    #[test]
    fn provider_identity_mismatch_is_typed() {
        let contract = PlatformProfileCandidateContract::v010_arch_hyprland_v1();
        let mut observation = PlatformObservation::default();
        for required in contract.required_facts() {
            let value =
                if required.key() == PlatformFactKey::Provider(PlatformProviderRole::Network) {
                    "systemd-networkd"
                } else {
                    required.expected()
                };
            observation
                .record_observed(required.key(), value, authority_for(required.key()))
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        }

        let result = contract
            .assess(&observation)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(matches!(
            result,
            PlatformProfileCompatibility::KnownMismatch { .. }
        ));
        if let PlatformProfileCompatibility::KnownMismatch { mismatches, .. } = result {
            assert_eq!(mismatches.len(), 1);
            assert_eq!(
                mismatches[0].key,
                PlatformFactKey::Provider(PlatformProviderRole::Network)
            );
            assert_eq!(mismatches[0].key.as_str(), "provider.network");
        }
    }

    #[test]
    fn duplicate_observation_cannot_silently_replace_evidence() {
        let mut observation = PlatformObservation::default();
        observation
            .record_observed(
                PlatformFactKey::Distribution,
                "arch",
                PlatformObservationAuthority::NativeOsRelease,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(
            observation.record_observed(
                PlatformFactKey::Distribution,
                "ubuntu",
                PlatformObservationAuthority::QualificationFixture,
            ),
            Err(PlatformProfileError::DuplicateObservationFact(
                PlatformFactKey::Distribution
            ))
        );
    }

    #[test]
    fn malformed_or_empty_evidence_fails_closed() {
        assert_eq!(
            PlatformFactEvidence::observed("   ", PlatformObservationAuthority::NativeOsRelease),
            Err(PlatformProfileError::InvalidEvidenceField(
                "platform fact value"
            ))
        );
        assert_eq!(
            PlatformFactEvidence::unavailable("\n"),
            Err(PlatformProfileError::InvalidEvidenceField(
                "platform evidence gap reason"
            ))
        );
    }
}
