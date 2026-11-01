//! S25: canonical owner-scoped personalization data; no native appearance effects.
//! The typed document is inert. Only a trusted Control composition may sign a
//! time-bounded local-state write; an imported theme never carries authority.

use linura_core::{PrincipalId, RequestId};

use crate::{
    AUTHORITY_MUTATION_TAG_BYTES, ContentDigest, TransactionAuthoritySigner,
    TransactionAuthorityVerifier, TransactionStoreError, TransactionValidationError, authority_tag,
    digest_bytes, mutation_field, verify_authority_tag,
};

pub const MAX_PERSONALIZATION_PREFERENCE_BYTES: usize = 4096;
pub const PERSONALIZATION_REQUEST_PREFIX: &str = "request:v010:personalization:";
const RECORD_DOMAIN: &str = "linura.personalization.preference-record.v1";
const UPDATE_DOMAIN: &str = "linura.personalization.preference-mutation.v1";

fn invalid() -> TransactionStoreError {
    TransactionStoreError::Corruption("personalization preference validation failed".into())
}

fn canonical_owner(owner: &PrincipalId) -> bool {
    owner
        .as_str()
        .strip_prefix("unix:uid:")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|uid| uid != 0 && owner.as_str() == format!("unix:uid:{uid}"))
}

fn canonical_request(request: &RequestId) -> bool {
    request
        .as_str()
        .strip_prefix(PERSONALIZATION_REQUEST_PREFIX)
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 128
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThemeMode {
    System,
    Light,
    Dark,
}
impl ThemeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
    fn parse(value: &str) -> Result<Self, TransactionStoreError> {
        match value {
            "system" => Ok(Self::System),
            "light" => Ok(Self::Light),
            "dark" => Ok(Self::Dark),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccentPreset {
    System,
    LinuraBlue,
}
impl AccentPreset {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::LinuraBlue => "linura-blue",
        }
    }
    fn parse(value: &str) -> Result<Self, TransactionStoreError> {
        match value {
            "system" => Ok(Self::System),
            "linura-blue" => Ok(Self::LinuraBlue),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Density {
    Standard,
    Spacious,
}
impl Density {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Spacious => "spacious",
        }
    }
    fn parse(value: &str) -> Result<Self, TransactionStoreError> {
        match value {
            "standard" => Ok(Self::Standard),
            "spacious" => Ok(Self::Spacious),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FontPreset {
    System,
    DejaVuSans,
}
impl FontPreset {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::DejaVuSans => "dejavu-sans",
        }
    }
    fn parse(value: &str) -> Result<Self, TransactionStoreError> {
        match value {
            "system" => Ok(Self::System),
            "dejavu-sans" => Ok(Self::DejaVuSans),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IconPreset {
    Linura,
}
impl IconPreset {
    fn as_str(self) -> &'static str {
        match self {
            Self::Linura => "linura",
        }
    }
    fn parse(value: &str) -> Result<Self, TransactionStoreError> {
        match value {
            "linura" => Ok(Self::Linura),
            _ => Err(invalid()),
        }
    }
}

/// Stored *intent* only; no field implies an installed font, imported icon,
/// safe decoded wallpaper, renderer application or permission to dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationChoices {
    pub mode: ThemeMode,
    pub accent: AccentPreset,
    pub density: Density,
    pub reduced_motion: bool,
    pub font: FontPreset,
    pub icons: IconPreset,
    pub wallpaper_digest: Option<ContentDigest>,
}
impl Default for PersonalizationChoices {
    fn default() -> Self {
        Self {
            mode: ThemeMode::System,
            accent: AccentPreset::System,
            density: Density::Standard,
            reduced_motion: false,
            font: FontPreset::System,
            icons: IconPreset::Linura,
            wallpaper_digest: None,
        }
    }
}

/// Monotonic, content-addressed owner preference revision. A requested
/// revision cannot skip history or replace a revision without an exact CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationPreferenceRecord {
    owner: PrincipalId,
    request: RequestId,
    revision: u64,
    previous_digest: Option<ContentDigest>,
    choices: PersonalizationChoices,
    canonical: Vec<u8>,
    digest: ContentDigest,
}

impl PersonalizationPreferenceRecord {
    pub fn new(
        owner: PrincipalId,
        request: RequestId,
        revision: u64,
        previous_digest: Option<ContentDigest>,
        choices: PersonalizationChoices,
    ) -> Result<Self, TransactionStoreError> {
        if !canonical_owner(&owner)
            || !canonical_request(&request)
            || revision == 0
            || (revision == 1) != previous_digest.is_none()
            || previous_digest.as_ref() == Some(&ContentDigest::zero())
            || choices.wallpaper_digest.as_ref() == Some(&ContentDigest::zero())
        {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let mut canonical = Vec::new();
        for value in [
            RECORD_DOMAIN,
            owner.as_str(),
            request.as_str(),
            &revision.to_string(),
            previous_digest.as_ref().map_or("", ContentDigest::as_str),
            choices.mode.as_str(),
            choices.accent.as_str(),
            choices.density.as_str(),
            if choices.reduced_motion {
                "true"
            } else {
                "false"
            },
            choices.font.as_str(),
            choices.icons.as_str(),
            choices
                .wallpaper_digest
                .as_ref()
                .map_or("", ContentDigest::as_str),
        ] {
            mutation_field(&mut canonical, value.as_bytes());
        }
        if canonical.len() > MAX_PERSONALIZATION_PREFERENCE_BYTES {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        let digest = digest_bytes(RECORD_DOMAIN, &canonical);
        Ok(Self {
            owner,
            request,
            revision,
            previous_digest,
            choices,
            canonical,
            digest,
        })
    }

    /// Strict canonical decode: no extra keys, duplicate fields, Unicode
    /// aliases, noncanonical numbers, trailing bytes or newer-schema fallback.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_PERSONALIZATION_PREFERENCE_BYTES {
            return Err(invalid());
        }
        let mut input = bytes;
        let mut field = || -> Result<&str, TransactionStoreError> {
            let (length, remaining) = input.split_at_checked(8).ok_or_else(invalid)?;
            let length: [u8; 8] = length.try_into().map_err(|_| invalid())?;
            let size = usize::try_from(u64::from_be_bytes(length)).map_err(|_| invalid())?;
            if size > 256 {
                return Err(invalid());
            }
            let (value, remaining) = remaining.split_at_checked(size).ok_or_else(invalid)?;
            input = remaining;
            std::str::from_utf8(value).map_err(|_| invalid())
        };
        let version = field()?;
        if version != RECORD_DOMAIN {
            return Err(TransactionStoreError::UnsupportedSchema(
                "unsupported personalization record generation".into(),
            ));
        }
        let owner = PrincipalId::new(field()?).map_err(|_| invalid())?;
        let request = RequestId::new(field()?).map_err(|_| invalid())?;
        let revision: u64 = field()?.parse().map_err(|_| invalid())?;
        let previous = match field()? {
            "" => None,
            value => Some(ContentDigest::new(value).map_err(|_| invalid())?),
        };
        let mode = ThemeMode::parse(field()?)?;
        let accent = AccentPreset::parse(field()?)?;
        let density = Density::parse(field()?)?;
        let reduced_motion = match field()? {
            "true" => true,
            "false" => false,
            _ => return Err(invalid()),
        };
        let font = FontPreset::parse(field()?)?;
        let icons = IconPreset::parse(field()?)?;
        let wallpaper_digest = match field()? {
            "" => None,
            value => Some(ContentDigest::new(value).map_err(|_| invalid())?),
        };
        if !input.is_empty() {
            return Err(invalid());
        }
        let record = Self::new(
            owner,
            request,
            revision,
            previous,
            PersonalizationChoices {
                mode,
                accent,
                density,
                reduced_motion,
                font,
                icons,
                wallpaper_digest,
            },
        )
        .map_err(|_| invalid())?;
        if record.canonical != bytes {
            return Err(invalid());
        }
        Ok(record)
    }

    #[must_use]
    pub const fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn previous_digest(&self) -> Option<&ContentDigest> {
        self.previous_digest.as_ref()
    }
    #[must_use]
    pub const fn choices(&self) -> &PersonalizationChoices {
        &self.choices
    }
    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// A Control-signed LinuraOwnedState write, not a native execution permit.
#[derive(Debug)]
pub struct PersonalizationPreferenceUpdate {
    record: PersonalizationPreferenceRecord,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    tag: [u8; AUTHORITY_MUTATION_TAG_BYTES],
}
impl PersonalizationPreferenceUpdate {
    #[must_use]
    pub const fn record(&self) -> &PersonalizationPreferenceRecord {
        &self.record
    }
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    #[must_use]
    pub fn authority_tag(&self) -> &[u8] {
        &self.tag
    }

    fn material(&self) -> Vec<u8> {
        mutation_material(
            &self.record,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
        )
    }
}
fn mutation_material(
    record: &PersonalizationPreferenceRecord,
    issued: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    mutation_field(&mut bytes, record.canonical());
    mutation_field(&mut bytes, &issued.to_be_bytes());
    mutation_field(&mut bytes, &expiry.to_be_bytes());
    bytes
}
fn bounded_expiry(issued: u64, expiry: u64) -> bool {
    issued != 0
        && expiry
            .checked_sub(issued)
            .is_some_and(|ttl| (1..=2000).contains(&ttl))
}
impl TransactionAuthoritySigner {
    /// Call only after a trusted transport binds the actual authenticated
    /// non-root principal and Control authorizes this exact local CAS request.
    pub fn authorize_personalization_preference(
        &self,
        record: PersonalizationPreferenceRecord,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<PersonalizationPreferenceUpdate, TransactionValidationError> {
        if !bounded_expiry(issued_at_unix_ms, expires_at_unix_ms) {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        let mut update = PersonalizationPreferenceUpdate {
            record,
            issued_at_unix_ms,
            expires_at_unix_ms,
            tag: [0; AUTHORITY_MUTATION_TAG_BYTES],
        };
        update.tag = authority_tag(&self.bytes, UPDATE_DOMAIN, &update.material())?;
        Ok(update)
    }
}
impl TransactionAuthorityVerifier {
    #[must_use]
    pub fn verify_personalization_preference(
        &self,
        update: &PersonalizationPreferenceUpdate,
    ) -> bool {
        self.verify_retained_personalization_preference(
            update.record(),
            update.issued_at_unix_ms(),
            update.expires_at_unix_ms(),
            update.authority_tag(),
        )
    }
    /// Verification of historical provenance is never permission to replay a
    /// superseded request or to bypass a fresh current-state revision check.
    #[must_use]
    pub fn verify_retained_personalization_preference(
        &self,
        record: &PersonalizationPreferenceRecord,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        tag: &[u8],
    ) -> bool {
        let Ok(tag): Result<&[u8; AUTHORITY_MUTATION_TAG_BYTES], _> = tag.try_into() else {
            return false;
        };
        bounded_expiry(issued_at_unix_ms, expires_at_unix_ms)
            && verify_authority_tag(
                &self.bytes,
                UPDATE_DOMAIN,
                &mutation_material(record, issued_at_unix_ms, expires_at_unix_ms),
                tag,
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransactionAuthorityKey;
    use std::fs::File;
    use std::io::Read;

    fn identity() -> (PrincipalId, RequestId) {
        (
            PrincipalId::new("unix:uid:1000").unwrap_or_else(|e| unreachable!("{e}")),
            RequestId::new("request:v010:personalization:12345678")
                .unwrap_or_else(|e| unreachable!("{e}")),
        )
    }
    fn first() -> PersonalizationPreferenceRecord {
        let (owner, request) = identity();
        PersonalizationPreferenceRecord::new(
            owner,
            request,
            1,
            None,
            PersonalizationChoices::default(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    #[test]
    fn canonical_roundtrip_and_strict_decode() {
        let record = first();
        assert_eq!(
            PersonalizationPreferenceRecord::decode(record.canonical()),
            Ok(record.clone())
        );
        for end in 0..record.canonical().len() {
            assert!(PersonalizationPreferenceRecord::decode(&record.canonical()[..end]).is_err());
        }
        let mut extra = record.canonical().to_vec();
        extra.push(0);
        assert!(PersonalizationPreferenceRecord::decode(&extra).is_err());
        assert!(
            PersonalizationPreferenceRecord::decode(&vec![
                0;
                MAX_PERSONALIZATION_PREFERENCE_BYTES + 1
            ])
            .is_err()
        );
        let mut huge = record.canonical().to_vec();
        huge[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(PersonalizationPreferenceRecord::decode(&huge).is_err());
    }
    #[test]
    fn rejects_foreign_identity_revision_gap_and_bad_requests() {
        for owner in [
            "unix:uid:0",
            "unix:uid:01000",
            "unix:uid:1001:extra",
            "human:1000",
        ] {
            let owner = PrincipalId::new(owner).unwrap_or_else(|e| unreachable!("{e}"));
            let (_, request) = identity();
            assert!(
                PersonalizationPreferenceRecord::new(
                    owner,
                    request,
                    1,
                    None,
                    PersonalizationChoices::default()
                )
                .is_err()
            );
        }
        let (owner, _) = identity();
        for bad in [
            "request:v010:personalization:",
            "request:v010:personalization:BAD",
            "request:other",
        ] {
            assert!(
                PersonalizationPreferenceRecord::new(
                    owner.clone(),
                    RequestId::new(bad).unwrap_or_else(|e| unreachable!("{e}")),
                    1,
                    None,
                    PersonalizationChoices::default()
                )
                .is_err()
            );
        }
        let (owner, request) = identity();
        assert!(
            PersonalizationPreferenceRecord::new(
                owner.clone(),
                request.clone(),
                0,
                None,
                PersonalizationChoices::default()
            )
            .is_err()
        );
        assert!(
            PersonalizationPreferenceRecord::new(
                owner,
                request,
                2,
                None,
                PersonalizationChoices::default()
            )
            .is_err()
        );
    }
    #[test]
    fn signed_mutation_is_purpose_and_deadline_bound() {
        let mut secret = Vec::new();
        let size = File::open("/dev/urandom")
            .and_then(|file| file.take(32).read_to_end(&mut secret))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(size, 32);
        let (signer, verifier) = TransactionAuthorityKey::new(secret)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .split();
        let record = first();
        for expiry in [1000, 3001, u64::MAX] {
            assert!(
                signer
                    .authorize_personalization_preference(record.clone(), 1000, expiry)
                    .is_err()
            );
        }
        let update = signer
            .authorize_personalization_preference(record.clone(), 1000, 2000)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(verifier.verify_personalization_preference(&update));
        assert!(!verifier.verify_retained_personalization_preference(
            &record,
            1000,
            2001,
            update.authority_tag()
        ));
        let alternate = PersonalizationPreferenceRecord::new(
            record.owner().clone(),
            RequestId::new("request:v010:personalization:other")
                .unwrap_or_else(|e| unreachable!("{e}")),
            1,
            None,
            PersonalizationChoices::default(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(!verifier.verify_retained_personalization_preference(
            &alternate,
            1000,
            2000,
            update.authority_tag()
        ));
    }
}
