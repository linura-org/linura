//! Canonical identity of a physical backlight during one exact login.
//!
//! A generation is assigned by trusted inventory only after independently
//! establishing physical lineage. Neither this type nor parsing it establishes
//! that evidence, a panel/seat mapping, qualification, or execution authority.
//! Kernel names, paths and inode numbers deliberately cannot stand in for a
//! non-reused device generation. Bounds, seat and qualification revisions remain
//! material authoritative observations bound by the canonical reviewed plan.

use std::fmt::{Display, Formatter};

use crate::{ResourceId, SessionEpoch, session_epoch::canonical_nonzero_uuid};

pub const BACKLIGHT_RESOURCE_PREFIX: &str = "backlight:physical:";
const EPOCH_PREFIX: &str = "session:epoch:";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BacklightDeviceGeneration(String);

impl BacklightDeviceGeneration {
    /// Validate identity syntax only. A caller-created UUID is not native
    /// lineage evidence; trusted inventory must reject reused generations.
    pub fn new(value: impl Into<String>) -> Result<Self, BacklightResourceError> {
        let value = value.into();
        if !canonical_nonzero_uuid(&value) {
            return Err(BacklightResourceError::InvalidDeviceGeneration);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BacklightResourceId {
    epoch: SessionEpoch,
    device_generation: BacklightDeviceGeneration,
}

impl BacklightResourceId {
    pub fn new(
        epoch: SessionEpoch,
        device_generation: BacklightDeviceGeneration,
    ) -> Result<Self, BacklightResourceError> {
        // logind treats UID 0 specially. It cannot be the original user subject
        // of this effect, even when its session identity is otherwise valid.
        if epoch.uid() == 0 || epoch.uid() == u32::MAX {
            return Err(BacklightResourceError::InvalidUserSubject);
        }
        Ok(Self {
            epoch,
            device_generation,
        })
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, BacklightResourceError> {
        let suffix = resource
            .as_str()
            .strip_prefix(BACKLIGHT_RESOURCE_PREFIX)
            .ok_or(BacklightResourceError::InvalidResource)?;
        let (epoch, generation) = suffix
            .rsplit_once(':')
            .ok_or(BacklightResourceError::InvalidResource)?;
        let epoch = ResourceId::new(format!("{EPOCH_PREFIX}{epoch}"))
            .map_err(|_| BacklightResourceError::InvalidResource)?;
        Self::new(
            SessionEpoch::from_resource(&epoch)
                .map_err(|_| BacklightResourceError::InvalidResource)?,
            BacklightDeviceGeneration::new(generation)?,
        )
    }

    pub fn resource_id(&self) -> Result<ResourceId, BacklightResourceError> {
        let epoch = self
            .epoch
            .resource_id()
            .map_err(|_| BacklightResourceError::InvalidResource)?;
        let epoch = epoch
            .as_str()
            .strip_prefix(EPOCH_PREFIX)
            .ok_or(BacklightResourceError::InvalidResource)?;
        ResourceId::new(format!(
            "{BACKLIGHT_RESOURCE_PREFIX}{epoch}:{}",
            self.device_generation.as_str()
        ))
        .map_err(|_| BacklightResourceError::InvalidResource)
    }

    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn device_generation(&self) -> &BacklightDeviceGeneration {
        &self.device_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightResourceError {
    InvalidDeviceGeneration,
    InvalidUserSubject,
    InvalidResource,
}

impl Display for BacklightResourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDeviceGeneration => {
                "backlight device generation must be a nonzero canonical lowercase UUID"
            }
            Self::InvalidUserSubject => "backlight requires a valid original non-root user",
            Self::InvalidResource => "backlight resource identity is not canonical",
        })
    }
}

impl std::error::Error for BacklightResourceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BootId;

    const BOOT: &str = "abcd1234-1234-4567-89ab-0123456789ab";
    const DEVICE: &str = "98765432-1234-4567-89ab-0123456789ab";

    fn valid<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn target(
        boot: &str,
        uid: u32,
        session: &str,
        created: u64,
        device: &str,
    ) -> BacklightResourceId {
        valid(BacklightResourceId::new(
            valid(SessionEpoch::new(
                valid(BootId::new(boot)),
                uid,
                session,
                created,
            )),
            valid(BacklightDeviceGeneration::new(device)),
        ))
    }

    #[test]
    fn resource_round_trips_without_a_native_path_or_ambient_session() {
        let target = target(BOOT, 1000, "c2", 42, DEVICE);
        let resource = valid(target.resource_id());
        assert_eq!(
            resource.as_str(),
            format!("backlight:physical:{BOOT}:1000:c2:42:{DEVICE}")
        );
        assert_eq!(valid(BacklightResourceId::from_resource(&resource)), target);
        assert_eq!(target.epoch().uid(), 1000);
        assert_eq!(target.device_generation().as_str(), DEVICE);
    }

    #[test]
    fn replacing_any_subject_or_generation_cannot_alias_a_reviewed_target() {
        let original = target(BOOT, 1000, "c2", 42, DEVICE);
        for changed in [
            target(
                "abcd1234-1234-4567-89ab-0123456789ac",
                1000,
                "c2",
                42,
                DEVICE,
            ),
            target(BOOT, 1001, "c2", 42, DEVICE),
            target(BOOT, 1000, "c3", 42, DEVICE),
            target(BOOT, 1000, "c2", 43, DEVICE),
            target(BOOT, 1000, "c2", 42, "98765432-1234-4567-89ab-0123456789ac"),
        ] {
            assert_ne!(original, changed);
            assert_ne!(valid(original.resource_id()), valid(changed.resource_id()));
        }
    }

    #[test]
    fn root_and_invalid_uid_cannot_be_substituted_for_the_native_user() {
        for uid in [0, u32::MAX] {
            assert_eq!(
                BacklightResourceId::new(
                    valid(SessionEpoch::new(valid(BootId::new(BOOT)), uid, "c2", 42)),
                    valid(BacklightDeviceGeneration::new(DEVICE)),
                ),
                Err(BacklightResourceError::InvalidUserSubject)
            );
            assert!(
                BacklightResourceId::from_resource(&valid(ResourceId::new(format!(
                    "backlight:physical:{BOOT}:{uid}:c2:42:{DEVICE}"
                ))))
                .is_err()
            );
        }
    }

    #[test]
    fn names_inodes_paths_nil_and_uuid_aliases_are_not_device_generations() {
        for generation in [
            "",
            "7",
            "intel_backlight",
            "/sys/class/backlight/intel_backlight",
            "../panel",
            "00000000-0000-0000-0000-000000000000",
            "98765432-1234-4567-89AB-0123456789AB",
            "98765432-1234-4567-89ab-0123456789ab:1",
        ] {
            assert!(BacklightDeviceGeneration::new(generation).is_err());
        }
    }

    #[test]
    fn partial_aliased_foreign_and_trailing_resources_fail_closed() {
        for suffix in [
            format!("{BOOT}:1000:c2:42"),
            format!("{BOOT}:01000:c2:42:{DEVICE}"),
            format!("{BOOT}:1000:self:42:{DEVICE}"),
            format!("{BOOT}:1000:auto:42:{DEVICE}"),
            format!("{BOOT}:1000:current:42:{DEVICE}"),
            format!("{BOOT}:1000:c2:042:{DEVICE}"),
            format!("{BOOT}:1000:c2:0:{DEVICE}"),
            format!("{BOOT}:1000:c2:42:{DEVICE}:extra"),
            format!("{BOOT}:1000:c2:42:intel_backlight"),
        ] {
            assert!(
                BacklightResourceId::from_resource(&valid(ResourceId::new(format!(
                    "{BACKLIGHT_RESOURCE_PREFIX}{suffix}"
                ))))
                .is_err(),
                "{suffix}"
            );
        }
        for resource in [
            "backlight:physical:intel_backlight",
            "session:epoch:current",
            "backlight:virtual:gamma",
        ] {
            assert!(BacklightResourceId::from_resource(&valid(ResourceId::new(resource))).is_err());
        }
    }

    #[test]
    fn maximum_supported_session_identity_fits_the_core_resource_budget() {
        let target = target(BOOT, u32::MAX - 1, &"s".repeat(64), u64::MAX, DEVICE);
        let resource = valid(target.resource_id());
        assert!(resource.as_str().len() <= 256);
        assert_eq!(valid(BacklightResourceId::from_resource(&resource)), target);
    }
}
