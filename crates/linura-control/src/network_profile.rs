//! S18-8 revision-aware, source-only NetworkManager saved-profile contracts.
//!
//! This module deliberately has no executor, D-Bus method names, serialized
//! raw NetworkManager maps, protected secrets, or public registered operation.
//! A successful comparison is correlation for future *independent* native
//! verification. It does NOT authorize AddConnection/Update2/Delete or commit
//! any durable transaction.

use std::collections::BTreeMap;

use linura_core::{NetworkManagerEpoch, NetworkProfileRevision};
use linura_transaction::{ContentDigest, TransactionState, digest_parts};

const MAX_PROFILE_LABEL_BYTES: usize = 96;
const MAX_WIFI_SSID_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileAddressMethod {
    Automatic,
    Disabled,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ProfileMedia {
    Ethernet,
    Wifi { ssid: Vec<u8> },
}

impl std::fmt::Debug for ProfileMedia {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ethernet => formatter.write_str("Ethernet"),
            Self::Wifi { .. } => formatter.write_str("Wifi { ssid: <private metadata> }"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileContractError {
    InvalidUuid,
    InvalidLabel,
    InvalidMedia,
    InvalidAddressMethods,
    WrongEpoch,
    WrongRevision,
    ChangedUuid,
    UnchangedSettings,
    MissingSource,
    UnexpectedSource,
    AmbiguousPostState,
    UnsafeDestructiveImpact,
    UnsupportedWireMutation,
    MissingProtectedWifiAuthority,
    UnsafeAutoconnect,
    UnexpectedNativeSettings,
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_LABEL_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b'.'))
}

/// Explicit nonsecret configuration. This is intentionally narrower than the
/// NetworkManager settings format: no arbitrary sections, gateway overrides,
/// DNS, routes, VPN, hotspot, key material, EAP or auth flags are accepted.
/// Unsupported configurations require another reviewed typed effect.
#[derive(Clone, Eq, PartialEq)]
pub struct NonSecretProfileDraft {
    uuid: String,
    label: String,
    media: ProfileMedia,
    ipv4: ProfileAddressMethod,
    ipv6: ProfileAddressMethod,
    autoconnect: bool,
}

impl std::fmt::Debug for NonSecretProfileDraft {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NonSecretProfileDraft")
            .field("uuid", &"<private metadata>")
            .field("label", &"<private metadata>")
            .field("media", &self.media)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("autoconnect", &self.autoconnect)
            .finish()
    }
}

impl NonSecretProfileDraft {
    pub fn new(
        uuid: impl Into<String>,
        label: impl Into<String>,
        media: ProfileMedia,
        ipv4: ProfileAddressMethod,
        ipv6: ProfileAddressMethod,
        autoconnect: bool,
    ) -> Result<Self, ProfileContractError> {
        let uuid = uuid.into();
        let label = label.into();
        if !valid_uuid(&uuid) {
            return Err(ProfileContractError::InvalidUuid);
        }
        if !valid_label(&label) {
            return Err(ProfileContractError::InvalidLabel);
        }
        if let ProfileMedia::Wifi { ssid } = &media
            && (ssid.is_empty() || ssid.len() > MAX_WIFI_SSID_BYTES)
        {
            return Err(ProfileContractError::InvalidMedia);
        }
        if ipv4 == ProfileAddressMethod::Disabled && ipv6 == ProfileAddressMethod::Disabled {
            return Err(ProfileContractError::InvalidAddressMethods);
        }
        Ok(Self {
            uuid,
            label,
            media,
            ipv4,
            ipv6,
            autoconnect,
        })
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// This content digest is *private request correlation*, not an attested
    /// NM settings revision, credential digest, authorization or audit value.
    /// No secret bytes enter this construction; SSIDs are not logged.
    pub fn private_correlation_digest(&self) -> ContentDigest {
        let medium = match &self.media {
            ProfileMedia::Ethernet => "ethernet",
            ProfileMedia::Wifi { .. } => "wifi",
        };
        let ssid = match &self.media {
            ProfileMedia::Ethernet => &[][..],
            ProfileMedia::Wifi { ssid } => ssid.as_slice(),
        };
        let family = |method: ProfileAddressMethod| match method {
            ProfileAddressMethod::Automatic => "automatic",
            ProfileAddressMethod::Disabled => "disabled",
        };
        digest_parts(
            "linura.s18-8.profile-draft.private.v1",
            [
                self.uuid.as_bytes(),
                self.label.as_bytes(),
                medium.as_bytes(),
                ssid,
                family(self.ipv4).as_bytes(),
                family(self.ipv6).as_bytes(),
                if self.autoconnect {
                    b"yes".as_slice()
                } else {
                    b"no".as_slice()
                },
            ],
        )
    }
}

/// The *only* nonsecret setting values admitted to the fixed NetworkManager
/// schema. No arbitrary variants, nested maps, routes, DNS, certificates,
/// credentials, or unvalidated caller-supplied section names are representable.
#[derive(Clone, Eq, PartialEq)]
pub enum FixedProfileSettingValue {
    Text(String),
    Boolean(bool),
}

impl std::fmt::Debug for FixedProfileSettingValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(_) => formatter.write_str("Text(<private>)"),
            Self::Boolean(_) => formatter.write_str("Boolean(<private>)"),
        }
    }
}

/// Immutable, precisely constructed settings *projection* for a future
/// original-user native encoder. An exact projection is not a D-Bus effect,
/// a complete policy decision, or a durable Control permit. A native sender
/// must independently prove authorization, UUID uniqueness and recovery.
#[derive(Clone, Eq, PartialEq)]
pub struct FixedNonSecretProfileSettings {
    sections: BTreeMap<&'static str, BTreeMap<&'static str, FixedProfileSettingValue>>,
}

impl std::fmt::Debug for FixedNonSecretProfileSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedNonSecretProfileSettings")
            .field("sections", &self.sections.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl FixedNonSecretProfileSettings {
    /// This initial nonsecret boundary supports *inactive Ethernet create
    /// projection only*. Never build a replacement Update2 map from this:
    /// Update2 replaces all settings, which can delete unknown, protected or
    /// shared profile fields. Wi-Fi requires a separately authorized secret/
    /// open-network policy and cannot be silently assumed open.
    pub fn inert_ethernet_create(
        draft: &NonSecretProfileDraft,
    ) -> Result<Self, ProfileContractError> {
        if draft.autoconnect {
            return Err(ProfileContractError::UnsafeAutoconnect);
        }
        if matches!(&draft.media, ProfileMedia::Wifi { .. }) {
            return Err(ProfileContractError::MissingProtectedWifiAuthority);
        }
        let method = |value: ProfileAddressMethod| {
            FixedProfileSettingValue::Text(
                match value {
                    ProfileAddressMethod::Automatic => "auto",
                    ProfileAddressMethod::Disabled => "disabled",
                }
                .to_owned(),
            )
        };
        let connection = BTreeMap::from([
            ("id", FixedProfileSettingValue::Text(draft.label.clone())),
            ("uuid", FixedProfileSettingValue::Text(draft.uuid.clone())),
            (
                "type",
                FixedProfileSettingValue::Text("802-3-ethernet".to_owned()),
            ),
            ("autoconnect", FixedProfileSettingValue::Boolean(false)),
        ]);
        let sections = BTreeMap::from([
            ("connection", connection),
            ("802-3-ethernet", BTreeMap::new()),
            ("ipv4", BTreeMap::from([("method", method(draft.ipv4))])),
            ("ipv6", BTreeMap::from([("method", method(draft.ipv6))])),
        ]);
        Ok(Self { sections })
    }

    /// Strictly compare the same tiny, nonsecret projection in an independent
    /// readback. The caller must still authenticate its actual native source.
    /// A matching object is *only correlation*, not verification of impact.
    pub fn require_exact_projection(&self, observed: &Self) -> Result<(), ProfileContractError> {
        if self != observed {
            return Err(ProfileContractError::UnexpectedNativeSettings);
        }
        Ok(())
    }

    pub fn sections(
        &self,
    ) -> &BTreeMap<&'static str, BTreeMap<&'static str, FixedProfileSettingValue>> {
        &self.sections
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileChange {
    Create,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileRecoveryRule {
    NoDispatch,
    ObserveOriginalStateOnly,
    AwaitDurableCommit,
    NeverReplay,
}

pub const fn recovery_rule(state: TransactionState) -> ProfileRecoveryRule {
    match state {
        TransactionState::Prepared => ProfileRecoveryRule::NoDispatch,
        TransactionState::Indeterminate | TransactionState::RecoveryBlocked => {
            ProfileRecoveryRule::ObserveOriginalStateOnly
        }
        TransactionState::Verified => ProfileRecoveryRule::AwaitDurableCommit,
        TransactionState::Committed | TransactionState::Aborted => ProfileRecoveryRule::NeverReplay,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRevisionIntent {
    change: ProfileChange,
    epoch: NetworkManagerEpoch,
    original: Option<NetworkProfileRevision>,
    proposal: Option<NonSecretProfileDraft>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileNativeEvidenceDisposition {
    /// Typed readback correlation alone is never a durable effect outcome.
    RequiresIndependentNativeQualification,
}

impl ProfileRevisionIntent {
    pub fn create(epoch: NetworkManagerEpoch, proposal: NonSecretProfileDraft) -> Self {
        Self {
            change: ProfileChange::Create,
            epoch,
            original: None,
            proposal: Some(proposal),
        }
    }

    pub fn update(
        original: NetworkProfileRevision,
        proposal: NonSecretProfileDraft,
    ) -> Result<Self, ProfileContractError> {
        if original.uuid() != proposal.uuid() {
            return Err(ProfileContractError::ChangedUuid);
        }
        Ok(Self {
            change: ProfileChange::Update,
            epoch: original.epoch().clone(),
            original: Some(original),
            proposal: Some(proposal),
        })
    }

    /// Delete carries no candidate settings and always remains destructive.
    /// An active/shared profile, remote admin path, dependent default route,
    /// missing offline local recovery or unknown impact must veto admission.
    pub fn delete(original: NetworkProfileRevision) -> Self {
        Self {
            change: ProfileChange::Delete,
            epoch: original.epoch().clone(),
            original: Some(original),
            proposal: None,
        }
    }

    pub const fn change(&self) -> ProfileChange {
        self.change
    }

    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    pub const fn original(&self) -> Option<&NetworkProfileRevision> {
        self.original.as_ref()
    }

    pub fn proposal(&self) -> Option<&NonSecretProfileDraft> {
        self.proposal.as_ref()
    }

    /// Reject substituted source identities and ABA revisions. The caller
    /// must still separately authenticate the original principal, ensure a
    /// complete coherent native profile inventory, and hold a durable permit.
    pub fn require_original(
        &self,
        native_current: Option<&NetworkProfileRevision>,
    ) -> Result<(), ProfileContractError> {
        match (self.change, &self.original, native_current) {
            (ProfileChange::Create, None, None) => Ok(()),
            (ProfileChange::Update | ProfileChange::Delete, Some(expected), Some(actual))
                if actual == expected && actual.epoch() == &self.epoch =>
            {
                Ok(())
            }
            (ProfileChange::Create, _, Some(_)) => Err(ProfileContractError::UnexpectedSource),
            (_, Some(_), None) => Err(ProfileContractError::MissingSource),
            _ => Err(ProfileContractError::WrongRevision),
        }
    }

    /// Independent follow-up readback is mandatory even for an NM method
    /// acknowledgement. These checks alone cannot produce a verified commit.
    pub fn assess_post_state(
        &self,
        native_before: Option<&NetworkProfileRevision>,
        native_after: Option<&NetworkProfileRevision>,
    ) -> Result<ProfileNativeEvidenceDisposition, ProfileContractError> {
        self.require_original(native_before)?;
        match (self.change, &self.original, &self.proposal, native_after) {
            (ProfileChange::Create, None, Some(draft), Some(after)) => {
                if after.epoch() != &self.epoch {
                    return Err(ProfileContractError::WrongEpoch);
                }
                if after.uuid() != draft.uuid() {
                    return Err(ProfileContractError::ChangedUuid);
                }
            }
            (ProfileChange::Update, Some(before), Some(draft), Some(after)) => {
                if after.epoch() != before.epoch()
                    || after.object() != before.object()
                    || after.uuid() != draft.uuid()
                {
                    return Err(ProfileContractError::WrongEpoch);
                }
                if after.revision_generation() <= before.revision_generation() {
                    return Err(ProfileContractError::WrongRevision);
                }
                if after.settings_fingerprint() == before.settings_fingerprint() {
                    return Err(ProfileContractError::UnchangedSettings);
                }
            }
            (ProfileChange::Delete, Some(_), None, None) => {}
            _ => return Err(ProfileContractError::AmbiguousPostState),
        }
        Ok(ProfileNativeEvidenceDisposition::RequiresIndependentNativeQualification)
    }

    /// None of the current caller-visible evidence proves original-session
    /// Polkit, a durable grant, shared-owner safety or offline restoration.
    /// A preview must never be promoted into authority.
    pub const fn dispatch_qualified(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProfileDeleteImpact {
    pub active_profile: bool,
    pub dependent_default_route: bool,
    pub shared_ownership: bool,
    pub remote_session_at_risk: bool,
    pub recovery_unverified: bool,
    pub native_impact_complete: bool,
}

impl ProfileDeleteImpact {
    /// Review-time rejection only. These values are not independently
    /// attestable and cannot authorize a physical delete.
    pub const fn reject_unsafe(self) -> Result<(), ProfileContractError> {
        if self.active_profile
            || self.dependent_default_route
            || self.shared_ownership
            || self.remote_session_at_risk
            || self.recovery_unverified
            || !self.native_impact_complete
        {
            return Err(ProfileContractError::UnsafeDestructiveImpact);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, NetworkManagerOwner, NetworkObjectId, NetworkObjectKind, SystemBusInstanceId,
    };

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("known test fixture: {error:?}"))
    }

    fn epoch(owner: &str) -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            ok(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            ok(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            ok(NetworkManagerOwner::new(owner)),
        )
    }

    fn revision(
        owner: &str,
        path: u64,
        generation: u64,
        fingerprint: char,
    ) -> NetworkProfileRevision {
        let native = format!("/org/freedesktop/NetworkManager/Settings/{path}");
        let bytes = std::iter::repeat_n(fingerprint, 64).collect::<String>();
        ok(NetworkProfileRevision::new(
            epoch(owner),
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                &native,
            )),
            "10203040-5060-7080-90ab-cdef12345678",
            generation,
            bytes,
        ))
    }

    fn draft() -> NonSecretProfileDraft {
        ok(NonSecretProfileDraft::new(
            "10203040-5060-7080-90ab-cdef12345678",
            "trusted-profile",
            ProfileMedia::Ethernet,
            ProfileAddressMethod::Automatic,
            ProfileAddressMethod::Automatic,
            false,
        ))
    }

    #[test]
    fn allowlisted_fields_cannot_smuggle_secret_maps_or_disabled_ip() {
        let valid = draft();
        assert!(
            valid
                .private_correlation_digest()
                .as_str()
                .starts_with("sha256:")
        );
        assert!(!format!("{valid:?}").contains("trusted-profile"));
        for name in ["", " shared", "VPN/secret", "bad\nlog", "a:b", "x "] {
            assert!(
                NonSecretProfileDraft::new(
                    valid.uuid(),
                    name,
                    ProfileMedia::Ethernet,
                    ProfileAddressMethod::Automatic,
                    ProfileAddressMethod::Automatic,
                    false,
                )
                .is_err()
            );
        }
        assert!(
            NonSecretProfileDraft::new(
                valid.uuid(),
                "valid",
                ProfileMedia::Wifi { ssid: vec![0; 33] },
                ProfileAddressMethod::Automatic,
                ProfileAddressMethod::Automatic,
                true,
            )
            .is_err()
        );
        assert!(
            NonSecretProfileDraft::new(
                valid.uuid(),
                "valid",
                ProfileMedia::Ethernet,
                ProfileAddressMethod::Disabled,
                ProfileAddressMethod::Disabled,
                true,
            )
            .is_err()
        );
        assert!(
            NonSecretProfileDraft::new(
                "00000000-0000-0000-0000-000000000000",
                "valid",
                ProfileMedia::Ethernet,
                ProfileAddressMethod::Automatic,
                ProfileAddressMethod::Automatic,
                false,
            )
            .is_err()
        );
        assert!(
            !format!(
                "{:?}",
                ProfileMedia::Wifi {
                    ssid: b"private-ssid".to_vec()
                }
            )
            .contains("private-ssid")
        );
    }

    #[test]
    fn fixed_nonsecret_creation_schema_rejects_unsafe_replacements_and_secrets() {
        let expected = ok(FixedNonSecretProfileSettings::inert_ethernet_create(
            &draft(),
        ));
        let names: Vec<_> = expected.sections().keys().copied().collect();
        assert_eq!(names, vec!["802-3-ethernet", "connection", "ipv4", "ipv6"]);
        assert_eq!(expected.sections()["connection"].len(), 4);
        assert!(expected.sections()["connection"].contains_key("uuid"));
        assert!(!expected.sections().contains_key("802-11-wireless-security"));
        assert!(!expected.sections().contains_key("vpn"));
        assert!(!expected.sections()["connection"].contains_key("permissions"));
        assert!(!format!("{expected:?}").contains("trusted-profile"));

        let other = ok(NonSecretProfileDraft::new(
            draft().uuid(),
            "renamed",
            ProfileMedia::Ethernet,
            ProfileAddressMethod::Automatic,
            ProfileAddressMethod::Automatic,
            false,
        ));
        let changed = ok(FixedNonSecretProfileSettings::inert_ethernet_create(&other));
        assert!(expected.require_exact_projection(&changed).is_err());

        let auto_connect = ok(NonSecretProfileDraft::new(
            draft().uuid(),
            "stable",
            ProfileMedia::Ethernet,
            ProfileAddressMethod::Automatic,
            ProfileAddressMethod::Automatic,
            true,
        ));
        assert_eq!(
            FixedNonSecretProfileSettings::inert_ethernet_create(&auto_connect),
            Err(ProfileContractError::UnsafeAutoconnect),
        );
        let wifi = ok(NonSecretProfileDraft::new(
            draft().uuid(),
            "ssid",
            ProfileMedia::Wifi {
                ssid: b"private-ssid".to_vec(),
            },
            ProfileAddressMethod::Automatic,
            ProfileAddressMethod::Automatic,
            false,
        ));
        assert_eq!(
            FixedNonSecretProfileSettings::inert_ethernet_create(&wifi),
            Err(ProfileContractError::MissingProtectedWifiAuthority),
        );
        assert!(!format!("{wifi:?}").contains("private-ssid"));
        assert!(!format!("{expected:?}").contains(draft().uuid()));
        assert!(expected.require_exact_projection(&expected).is_ok());
        // A fixed projection is never a native send grant.
        assert!(!ProfileRevisionIntent::create(epoch(":1.48"), draft()).dispatch_qualified());
    }

    #[test]
    fn source_revision_requires_exact_epoch_object_generation_and_fingerprint() {
        let before = revision(":1.48", 9, 10, 'a');
        let update = ok(ProfileRevisionIntent::update(before.clone(), draft()));
        assert!(update.require_original(Some(&before)).is_ok());
        for changed in [
            revision(":1.49", 9, 10, 'a'),
            revision(":1.48", 10, 10, 'a'),
            revision(":1.48", 9, 11, 'a'),
            revision(":1.48", 9, 10, 'b'),
        ] {
            assert!(update.require_original(Some(&changed)).is_err());
            assert!(update.assess_post_state(Some(&changed), None).is_err());
        }
        assert!(update.require_original(None).is_err());
        let after = revision(":1.48", 9, 11, 'b');
        assert_eq!(
            update.assess_post_state(Some(&before), Some(&after)),
            Ok(ProfileNativeEvidenceDisposition::RequiresIndependentNativeQualification)
        );
        assert!(
            update
                .assess_post_state(Some(&before), Some(&before))
                .is_err()
        );
        assert!(
            update
                .assess_post_state(Some(&before), Some(&revision(":1.48", 9, 11, 'a')))
                .is_err()
        );
        assert!(
            update
                .assess_post_state(Some(&before), Some(&revision(":1.48", 10, 11, 'b')))
                .is_err()
        );
        assert!(!update.dispatch_qualified());
    }

    #[test]
    fn create_delete_and_ambiguous_effects_never_confer_authority() {
        let expected = revision(":1.48", 9, 10, 'a');
        let create = ProfileRevisionIntent::create(epoch(":1.48"), draft());
        assert!(create.require_original(None).is_ok());
        assert!(create.require_original(Some(&expected)).is_err());
        assert!(create.assess_post_state(None, Some(&expected)).is_ok());
        assert!(create.assess_post_state(None, None).is_err());
        assert!(
            create
                .assess_post_state(None, Some(&revision(":1.49", 9, 10, 'a')))
                .is_err()
        );

        let delete = ProfileRevisionIntent::delete(expected.clone());
        assert_eq!(delete.change(), ProfileChange::Delete);
        assert!(delete.assess_post_state(Some(&expected), None).is_ok());
        assert!(
            delete
                .assess_post_state(Some(&expected), Some(&expected))
                .is_err()
        );
        assert!(!delete.dispatch_qualified());

        let proposed = ProfileDeleteImpact::default();
        assert!(proposed.reject_unsafe().is_err());
        let reviewed = ProfileDeleteImpact {
            native_impact_complete: true,
            ..proposed
        };
        assert!(reviewed.reject_unsafe().is_ok());
        for unsafe_case in [
            ProfileDeleteImpact {
                active_profile: true,
                ..reviewed
            },
            ProfileDeleteImpact {
                dependent_default_route: true,
                ..reviewed
            },
            ProfileDeleteImpact {
                shared_ownership: true,
                ..reviewed
            },
            ProfileDeleteImpact {
                remote_session_at_risk: true,
                ..reviewed
            },
            ProfileDeleteImpact {
                recovery_unverified: true,
                ..reviewed
            },
        ] {
            assert!(unsafe_case.reject_unsafe().is_err());
        }
        for state in [
            TransactionState::Indeterminate,
            TransactionState::RecoveryBlocked,
        ] {
            assert_eq!(
                recovery_rule(state),
                ProfileRecoveryRule::ObserveOriginalStateOnly
            );
        }
        assert_eq!(
            recovery_rule(TransactionState::Prepared),
            ProfileRecoveryRule::NoDispatch
        );
        assert_eq!(
            recovery_rule(TransactionState::Committed),
            ProfileRecoveryRule::NeverReplay
        );
        assert_eq!(
            recovery_rule(TransactionState::Aborted),
            ProfileRecoveryRule::NeverReplay
        );
    }
}
