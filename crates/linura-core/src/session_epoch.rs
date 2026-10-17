//! Session resource identity, independent of transport handles and caller authority.
//!
//! A session name, user id, or process id alone is not a generation: all can be
//! reused. The boot and session creation generation must remain bound through
//! planning, approval, dispatch and recovery. Possession of this identity grants
//! no permission to observe or change the identified session.

use std::fmt::{Display, Formatter};

use crate::ResourceId;

const RESOURCE_PREFIX: &str = "session:epoch:";
const MAX_SESSION_ID_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BootId(String);

impl BootId {
    pub fn new(value: impl Into<String>) -> Result<Self, SessionEpochError> {
        let value = value.into();
        if !canonical_nonzero_uuid(&value) {
            return Err(SessionEpochError::InvalidBootId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The native supervisor's unique invocation of a security-owning process.
/// It is identity/correlation, never an approval or executor credential. The
/// trusted adapter must attest it independently of caller-provided resource IDs.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecurityOwnerInvocationId(String);

impl SecurityOwnerInvocationId {
    pub fn new(value: impl Into<String>) -> Result<Self, SessionEpochError> {
        let value = value.into();
        if !canonical_nonzero_uuid(&value) {
            return Err(SessionEpochError::InvalidSecurityOwnerInvocation);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn canonical_nonzero_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionEpoch {
    boot: BootId,
    uid: u32,
    session_id: String,
    created_monotonic_us: u64,
}

impl SessionEpoch {
    pub fn new(
        boot: BootId,
        uid: u32,
        session_id: impl Into<String>,
        created_monotonic_us: u64,
    ) -> Result<Self, SessionEpochError> {
        let session_id = session_id.into();
        if session_id.is_empty()
            || session_id.len() > MAX_SESSION_ID_BYTES
            || !session_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(SessionEpochError::InvalidSessionId);
        }
        if created_monotonic_us == 0 {
            return Err(SessionEpochError::InvalidCreationGeneration);
        }
        Ok(Self {
            boot,
            uid,
            session_id,
            created_monotonic_us,
        })
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, SessionEpochError> {
        let suffix = resource
            .as_str()
            .strip_prefix(RESOURCE_PREFIX)
            .ok_or(SessionEpochError::InvalidResource)?;
        let fields: Vec<_> = suffix.split(':').collect();
        let [boot, uid, session_id, created] = fields.as_slice() else {
            return Err(SessionEpochError::InvalidResource);
        };
        let uid = canonical_u64(uid)?;
        let uid = u32::try_from(uid).map_err(|_| SessionEpochError::InvalidResource)?;
        Self::new(
            BootId::new(*boot)?,
            uid,
            *session_id,
            canonical_u64(created)?,
        )
    }

    pub fn resource_id(&self) -> Result<ResourceId, SessionEpochError> {
        ResourceId::new(format!(
            "{RESOURCE_PREFIX}{}:{}:{}:{}",
            self.boot.as_str(),
            self.uid,
            self.session_id,
            self.created_monotonic_us
        ))
        .map_err(|_| SessionEpochError::InvalidResource)
    }

    #[must_use]
    pub const fn boot(&self) -> &BootId {
        &self.boot
    }

    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn created_monotonic_us(&self) -> u64 {
        self.created_monotonic_us
    }
}

/// Identity of one native compositor lock, not a reusable session credential.
/// Unlock approvals for a previous lock must never unlock a subsequent lock in
/// the same login session. Bind both the attested security-owner invocation and
/// its nonzero lock counter: restarting the owner cannot reset the counter into
/// an identity previously approved during the same login session.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionLockId {
    epoch: SessionEpoch,
    security_owner_invocation: SecurityOwnerInvocationId,
    generation: u64,
}

impl SessionLockId {
    pub fn new(
        epoch: SessionEpoch,
        security_owner_invocation: SecurityOwnerInvocationId,
        generation: u64,
    ) -> Result<Self, SessionEpochError> {
        if generation == 0 {
            return Err(SessionEpochError::InvalidLockGeneration);
        }
        Ok(Self {
            epoch,
            security_owner_invocation,
            generation,
        })
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, SessionEpochError> {
        let suffix = resource
            .as_str()
            .strip_prefix("session:lock:")
            .ok_or(SessionEpochError::InvalidResource)?;
        let (scope, generation) = suffix
            .rsplit_once(':')
            .ok_or(SessionEpochError::InvalidResource)?;
        let (epoch, invocation) = scope
            .rsplit_once(':')
            .ok_or(SessionEpochError::InvalidResource)?;
        let epoch = ResourceId::new(format!("{RESOURCE_PREFIX}{epoch}"))
            .map_err(|_| SessionEpochError::InvalidResource)?;
        Self::new(
            SessionEpoch::from_resource(&epoch)?,
            SecurityOwnerInvocationId::new(invocation)?,
            canonical_u64(generation)?,
        )
    }

    pub fn resource_id(&self) -> Result<ResourceId, SessionEpochError> {
        let epoch = self.epoch.resource_id()?;
        let suffix = epoch
            .as_str()
            .strip_prefix(RESOURCE_PREFIX)
            .ok_or(SessionEpochError::InvalidResource)?;
        ResourceId::new(format!(
            "session:lock:{suffix}:{}:{}",
            self.security_owner_invocation.as_str(),
            self.generation
        ))
        .map_err(|_| SessionEpochError::InvalidResource)
    }

    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn security_owner_invocation(&self) -> &SecurityOwnerInvocationId {
        &self.security_owner_invocation
    }
}

fn canonical_u64(value: &str) -> Result<u64, SessionEpochError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SessionEpochError::InvalidResource);
    }
    value
        .parse()
        .map_err(|_| SessionEpochError::InvalidResource)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEpochError {
    InvalidBootId,
    InvalidSessionId,
    InvalidCreationGeneration,
    InvalidLockGeneration,
    InvalidSecurityOwnerInvocation,
    InvalidResource,
}

impl Display for SessionEpochError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBootId => "boot identity must be a nonzero canonical lowercase UUID",
            Self::InvalidSessionId => "session identity must be 1..64 ASCII letters or digits",
            Self::InvalidCreationGeneration => "session creation generation must be nonzero",
            Self::InvalidLockGeneration => "native lock generation must be nonzero",
            Self::InvalidSecurityOwnerInvocation => {
                "security-owner invocation must be a nonzero canonical lowercase UUID"
            }
            Self::InvalidResource => "session epoch resource is not canonical",
        })
    }
}

impl std::error::Error for SessionEpochError {}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "abcd1234-1234-4567-89ab-0123456789ab";
    const INVOCATION: &str = "98765432-1234-4567-89ab-0123456789ab";

    fn invocation() -> SecurityOwnerInvocationId {
        id(SecurityOwnerInvocationId::new(INVOCATION))
    }

    #[test]
    fn lock_identity_is_exact_and_cannot_alias_another_lock_or_session() {
        let epoch = id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "c2", 42));
        let lock = id(SessionLockId::new(epoch.clone(), invocation(), 7));
        let resource = id(lock.resource_id());
        assert_eq!(
            resource.as_str(),
            format!("session:lock:{BOOT}:1000:c2:42:{INVOCATION}:7")
        );
        assert_eq!(id(SessionLockId::from_resource(&resource)), lock);
        assert_ne!(lock, id(SessionLockId::new(epoch.clone(), invocation(), 8)));
        let replacement = id(SecurityOwnerInvocationId::new(
            "98765432-1234-4567-89ab-0123456789ac",
        ));
        assert_ne!(lock, id(SessionLockId::new(epoch.clone(), replacement, 7)));
        assert!(SessionLockId::new(epoch.clone(), invocation(), 0).is_err());
        assert!(SessionLockId::from_resource(&id(epoch.resource_id())).is_err());
        for suffix in ["0", "07", "+7", "7:8", "18446744073709551616"] {
            let malformed = id(ResourceId::new(format!(
                "session:lock:{BOOT}:1000:c2:42:{INVOCATION}:{suffix}"
            )));
            assert!(SessionLockId::from_resource(&malformed).is_err());
        }
        assert!(
            SessionLockId::from_resource(&id(ResourceId::new(format!(
                "session:lock:{BOOT}:1000:c2:42:7"
            ))))
            .is_err()
        );
    }

    #[test]
    fn security_owner_invocation_rejects_missing_nil_and_aliased_identity() {
        for invalid in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "98765432-1234-4567-89AB-0123456789AB",
            "98765432-1234-4567-89ab-0123456789ab:7",
        ] {
            assert!(SecurityOwnerInvocationId::new(invalid).is_err());
        }
    }

    fn id<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    #[test]
    fn epoch_resource_has_one_exact_round_trip() {
        let epoch = id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "c2", 42));
        let resource = id(epoch.resource_id());
        assert_eq!(
            resource.as_str(),
            format!("session:epoch:{BOOT}:1000:c2:42")
        );
        assert_eq!(id(SessionEpoch::from_resource(&resource)), epoch);
    }

    #[test]
    fn every_generation_and_owner_component_changes_identity() {
        let original = id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "2", 42));
        for changed in [
            id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ac")),
                1000,
                "2",
                42,
            )),
            id(SessionEpoch::new(id(BootId::new(BOOT)), 1001, "2", 42)),
            id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "3", 42)),
            id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "2", 43)),
        ] {
            assert_ne!(original, changed);
            assert_ne!(id(original.resource_id()), id(changed.resource_id()));
        }
    }

    #[test]
    fn boot_ids_reject_aliases_and_unknown_identity() {
        for boot in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "ABCD1234-1234-4567-89AB-0123456789AB",
            "abcd1234_1234-4567-89ab-0123456789ab",
            "abcd1234-1234-4567-89ab-0123456789ab\n",
        ] {
            assert!(BootId::new(boot).is_err(), "{boot:?}");
        }
    }

    #[test]
    fn session_resources_reject_ambiguous_partial_and_substituted_identity() {
        for suffix in [
            "1000:2:0",
            "01000:2:42",
            "+1000:2:42",
            "4294967296:2:42",
            "1000:2:042",
            "1000:2:18446744073709551616",
            "1000:self:42:extra",
            "1000:../2:42",
            "1000::42",
            "1000:2",
        ] {
            let resource = id(ResourceId::new(format!("session:epoch:{BOOT}:{suffix}")));
            assert!(SessionEpoch::from_resource(&resource).is_err(), "{suffix}");
        }
        assert!(SessionEpoch::from_resource(&id(ResourceId::new("session:current"))).is_err());
        assert!(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "x".repeat(65), 1).is_err());
        assert!(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "é", 1).is_err());
    }
}
