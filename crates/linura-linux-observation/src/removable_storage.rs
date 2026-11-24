//! S21-4: bounded, non-authorizing removable-storage topology and safety review.
//!
//! These are candidate native *facts*, not credentials or an execution permit.
//! A future trusted adapter must independently authenticate the D-Bus/kernel
//! source, selected logind session, mount namespace and Polkit calling subject.
//! A caller-supplied snapshot must NEVER authorize a storage mutation.
//! Control must retain canonical managed prepare, policy and no-replay recovery.
//! There is intentionally no D-Bus mutation, mount option or privileged API.

use std::collections::BTreeSet;

pub const UDISKS2_PROVIDER: &str = "udisks2";
pub const REMOVABLE_STORAGE_CAPABILITY: &str = "storage.removable.observe";
pub const MAX_STORAGE_OBSERVATION_AGE_MS: u64 = 2_000;
const MAX_DRIVES: usize = 32;
const MAX_BLOCKS: usize = 128;
const MAX_MOUNTPOINTS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageSource {
    /// Source correlations are not independent proof of provenance.
    pub boot_id: String,
    pub provider_unique_name: String,
    pub provider_generation: u64,
    pub topology_generation: u64,
    pub session_id: String,
    pub seat_id: String,
    pub caller_unique_name: String,
    pub caller_uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageBlock {
    pub object_path: String,
    pub device_number: u64,
    pub generation: u64,
    pub has_filesystem: bool,
    pub partition_number: Option<u32>,
    pub mount_points: Vec<String>,
    /// Must be determined from kernel-native use / ownership evidence.
    pub busy: bool,
    /// Includes root, boot, swap, and other protected host devices.
    pub system: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageDrive {
    pub object_path: String,
    pub sysfs_path: String,
    pub generation: u64,
    pub removable: bool,
    pub media_available: bool,
    pub ejectable: bool,
    pub can_power_off: bool,
    /// Observed seat; not itself a source of authenticated caller authority.
    pub seat_id: String,
    /// Shared physical-removal group; must include every affected sibling.
    pub sibling_id: String,
    /// A complete physical-child / sibling inventory, not a selected subset.
    pub blocks: Vec<StorageBlock>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageTopology {
    pub source: StorageSource,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub valid_for_ms: u64,
    pub complete_inventory: bool,
    pub drives: Vec<StorageDrive>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAction {
    Mount,
    Unmount,
    Eject,
    PowerOff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRisk {
    SecuritySensitive,
    Destructive,
}

impl StorageAction {
    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Mount => "operation:storage.filesystem.mount",
            Self::Unmount => "operation:storage.filesystem.unmount",
            Self::Eject => "operation:storage.drive.eject",
            Self::PowerOff => "operation:storage.drive.power-off",
        }
    }

    #[must_use]
    pub const fn risk_floor(self) -> StorageRisk {
        match self {
            Self::Mount => StorageRisk::SecuritySensitive,
            Self::Unmount | Self::Eject | Self::PowerOff => StorageRisk::Destructive,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageTarget {
    pub drive_object: String,
    pub drive_generation: u64,
    pub block_object: Option<String>,
    pub block_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageRequest {
    pub action: StorageAction,
    pub target: StorageTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageReviewError {
    InvalidSnapshot,
    StaleObservation,
    ChangedSourceOrPrincipal,
    ChangedTopology,
    MissingOrReplacedTarget,
    UnsupportedOrProtectedMedia,
    BusyOrMountedSibling,
    AmbiguousMountState,
    AlreadySatisfied,
    UnsupportedMethod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePreflight {
    /// An advisory safety decision only, *never* an executor/approval permit.
    pub request: StorageRequest,
    pub live: StorageTopology,
    pub risk_floor: StorageRisk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePostcondition {
    /// Native topology is consistent with the requested change. This is NOT
    /// a Control commit or independently authenticated success receipt.
    ConsistentNativeState,
    Indeterminate,
    /// Eject and PowerOff require separately qualified physical proof.
    UnprovenPhysicalEffect,
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_unique_bus_name(value: &str) -> bool {
    value.starts_with(':')
        && value.len() <= 128
        && value[1..].split('.').count() >= 2
        && value[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_object_path(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() <= 256
        && value.len() > prefix.len()
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_sysfs_path(value: &str) -> bool {
    value.starts_with("/sys/devices/")
        && value.len() <= 1024
        && !value.bytes().any(|b| b.is_ascii_control() || b == b'\\')
        && !value.split('/').any(|part| part == "." || part == "..")
}

fn valid_mount_point(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && value.len() <= 4096
        && !value.bytes().any(|b| b.is_ascii_control())
        && !value.split('/').any(|part| part == "." || part == "..")
}

impl StorageTopology {
    /// Validate shape only. No client can attest its own source of authority.
    pub fn validate(&self, now_ms: u64) -> Result<(), StorageReviewError> {
        let s = &self.source;
        if !valid_token(&s.boot_id)
            || !valid_token(&s.session_id)
            || !valid_token(&s.seat_id)
            || !valid_unique_bus_name(&s.provider_unique_name)
            || !valid_unique_bus_name(&s.caller_unique_name)
            || s.caller_uid == 0
            || s.provider_generation == 0
            || s.topology_generation == 0
            || self.sequence == 0
            || !self.complete_inventory
            || self.drives.len() > MAX_DRIVES
        {
            return Err(StorageReviewError::InvalidSnapshot);
        }
        if self.valid_for_ms == 0
            || self.valid_for_ms > MAX_STORAGE_OBSERVATION_AGE_MS
            || now_ms < self.observed_at_ms
            || now_ms - self.observed_at_ms > self.valid_for_ms
        {
            return Err(StorageReviewError::StaleObservation);
        }

        let mut objects = BTreeSet::new();
        let mut devices = BTreeSet::new();
        let mut block_count = 0usize;
        for drive in &self.drives {
            if !valid_object_path(&drive.object_path, "/org/freedesktop/UDisks2/drives/")
                || !valid_sysfs_path(&drive.sysfs_path)
                || drive.generation == 0
                || !objects.insert(drive.object_path.as_str())
            {
                return Err(StorageReviewError::InvalidSnapshot);
            }
            block_count += drive.blocks.len();
            if block_count > MAX_BLOCKS {
                return Err(StorageReviewError::InvalidSnapshot);
            }
            for block in &drive.blocks {
                if !valid_object_path(
                    &block.object_path,
                    "/org/freedesktop/UDisks2/block_devices/",
                ) || block.generation == 0
                    || block.device_number == 0
                    || !objects.insert(block.object_path.as_str())
                    || !devices.insert(block.device_number)
                    || block.mount_points.len() > MAX_MOUNTPOINTS
                    || (!block.has_filesystem && !block.mount_points.is_empty())
                    || !block
                        .mount_points
                        .iter()
                        .all(|path| valid_mount_point(path))
                    || block.mount_points.iter().collect::<BTreeSet<_>>().len()
                        != block.mount_points.len()
                {
                    return Err(StorageReviewError::InvalidSnapshot);
                }
            }
        }
        Ok(())
    }

    fn target(
        &self,
        target: &StorageTarget,
    ) -> Result<(&StorageDrive, Option<&StorageBlock>), StorageReviewError> {
        let drive = self
            .drives
            .iter()
            .find(|drive| drive.object_path == target.drive_object)
            .ok_or(StorageReviewError::MissingOrReplacedTarget)?;
        if target.drive_generation == 0 || drive.generation != target.drive_generation {
            return Err(StorageReviewError::MissingOrReplacedTarget);
        }
        let block = match (&target.block_object, target.block_generation) {
            (None, None) => None,
            (Some(path), Some(generation)) if generation != 0 => {
                let block = drive
                    .blocks
                    .iter()
                    .find(|block| block.object_path == *path)
                    .ok_or(StorageReviewError::MissingOrReplacedTarget)?;
                if block.generation != generation {
                    return Err(StorageReviewError::MissingOrReplacedTarget);
                }
                Some(block)
            }
            _ => return Err(StorageReviewError::MissingOrReplacedTarget),
        };
        Ok((drive, block))
    }
}

/// Compare two independently collected *candidate* snapshots. A future
/// Control caller must separately prove that both were observed by its
/// authenticated native source and bind them to original managed authority.
pub fn review_storage_preflight(
    approved: &StorageTopology,
    fresh: &StorageTopology,
    authenticated_caller_uid: u32,
    request: StorageRequest,
    now_ms: u64,
) -> Result<StoragePreflight, StorageReviewError> {
    approved.validate(now_ms)?;
    fresh.validate(now_ms)?;
    if approved.source != fresh.source
        || authenticated_caller_uid == 0
        || fresh.source.caller_uid != authenticated_caller_uid
    {
        return Err(StorageReviewError::ChangedSourceOrPrincipal);
    }
    if fresh.sequence <= approved.sequence || approved.drives != fresh.drives {
        return Err(StorageReviewError::ChangedTopology);
    }
    let (drive, block) = fresh.target(&request.target)?;
    if !drive.removable
        || !drive.media_available
        || drive.seat_id != fresh.source.seat_id
        || drive.blocks.is_empty()
        || drive.blocks.iter().any(|item| item.system)
    {
        return Err(StorageReviewError::UnsupportedOrProtectedMedia);
    }
    match request.action {
        StorageAction::Mount => {
            let block = block.ok_or(StorageReviewError::MissingOrReplacedTarget)?;
            if !block.has_filesystem {
                return Err(StorageReviewError::UnsupportedMethod);
            }
            if block.busy {
                return Err(StorageReviewError::BusyOrMountedSibling);
            }
            if !block.mount_points.is_empty() {
                return Err(StorageReviewError::AlreadySatisfied);
            }
        }
        StorageAction::Unmount => {
            let block = block.ok_or(StorageReviewError::MissingOrReplacedTarget)?;
            if !block.has_filesystem {
                return Err(StorageReviewError::UnsupportedMethod);
            }
            if block.busy {
                return Err(StorageReviewError::BusyOrMountedSibling);
            }
            if block.mount_points.is_empty() {
                return Err(StorageReviewError::AlreadySatisfied);
            }
            if block.mount_points.len() != 1 {
                return Err(StorageReviewError::AmbiguousMountState);
            }
        }
        StorageAction::Eject | StorageAction::PowerOff => {
            if block.is_some() {
                return Err(StorageReviewError::MissingOrReplacedTarget);
            }
            if !valid_token(&drive.sibling_id) {
                return Err(StorageReviewError::UnsupportedOrProtectedMedia);
            }
            let siblings: Vec<_> = fresh
                .drives
                .iter()
                .filter(|candidate| candidate.sibling_id == drive.sibling_id)
                .collect();
            if siblings.is_empty()
                || siblings.iter().any(|candidate| {
                    candidate.seat_id != fresh.source.seat_id
                        || !candidate.removable
                        || candidate.blocks.is_empty()
                        || candidate.blocks.iter().any(|block| block.system)
                })
            {
                return Err(StorageReviewError::UnsupportedOrProtectedMedia);
            }
            if siblings.iter().any(|candidate| {
                candidate
                    .blocks
                    .iter()
                    .any(|b| b.busy || !b.mount_points.is_empty())
            }) {
                return Err(StorageReviewError::BusyOrMountedSibling);
            }
            let supported = match request.action {
                StorageAction::Eject => drive.ejectable,
                StorageAction::PowerOff => drive.can_power_off,
                StorageAction::Mount | StorageAction::Unmount => false,
            };
            if !supported {
                return Err(StorageReviewError::UnsupportedMethod);
            }
        }
    }
    Ok(StoragePreflight {
        risk_floor: request.action.risk_floor(),
        request,
        live: fresh.clone(),
    })
}

/// A separate, newer native observation must support mount/unmount. The
/// executor's reply is irrelevant. Never classify disappearing devices or
/// an incomplete inventory as success. Physical eject and power-off evidence
/// requires an independent oracle not present in this candidate model.
#[must_use]
pub fn review_storage_postcondition(
    before: &StoragePreflight,
    after: &StorageTopology,
    now_ms: u64,
) -> StoragePostcondition {
    if matches!(
        before.request.action,
        StorageAction::Eject | StorageAction::PowerOff
    ) {
        return StoragePostcondition::UnprovenPhysicalEffect;
    }
    if after.validate(now_ms).is_err()
        || before.live.source != after.source
        || after.sequence <= before.live.sequence
        || before.live.drives.len() != after.drives.len()
    {
        return StoragePostcondition::Indeterminate;
    }
    let mut expected = before.live.clone();
    let Ok((drive, block)) = after.target(&before.request.target) else {
        return StoragePostcondition::Indeterminate;
    };
    let Some(block) = block else {
        return StoragePostcondition::Indeterminate;
    };
    let mount_ok = match before.request.action {
        StorageAction::Mount => block.mount_points.len() == 1,
        StorageAction::Unmount => block.mount_points.is_empty(),
        StorageAction::Eject | StorageAction::PowerOff => false,
    };
    if !mount_ok || !drive.media_available || !drive.removable {
        return StoragePostcondition::Indeterminate;
    }
    for original_drive in &mut expected.drives {
        if original_drive.object_path != before.request.target.drive_object {
            continue;
        }
        for original_block in &mut original_drive.blocks {
            if Some(original_block.object_path.as_str())
                == before.request.target.block_object.as_deref()
            {
                original_block.mount_points.clone_from(&block.mount_points);
            }
        }
    }
    if expected.drives == after.drives {
        StoragePostcondition::ConsistentNativeState
    } else {
        StoragePostcondition::Indeterminate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> StorageTopology {
        StorageTopology {
            source: StorageSource {
                boot_id: "da6d8c33-0fd4-4bba-b297-97d7b7437764".into(),
                provider_unique_name: ":1.42".into(),
                provider_generation: 3,
                topology_generation: 7,
                session_id: "c2".into(),
                seat_id: "seat0".into(),
                caller_unique_name: ":1.101".into(),
                caller_uid: 1000,
            },
            observed_at_ms: 1000,
            valid_for_ms: 500,
            sequence: 1,
            complete_inventory: true,
            drives: vec![StorageDrive {
                object_path: "/org/freedesktop/UDisks2/drives/usb1".into(),
                sysfs_path: "/sys/devices/pci0000:00/usb1".into(),
                generation: 9,
                removable: true,
                media_available: true,
                ejectable: true,
                can_power_off: true,
                seat_id: "seat0".into(),
                sibling_id: "physical-group-1".into(),
                blocks: vec![StorageBlock {
                    object_path: "/org/freedesktop/UDisks2/block_devices/sdb1".into(),
                    device_number: 2050,
                    generation: 5,
                    has_filesystem: true,
                    partition_number: Some(1),
                    mount_points: vec![],
                    busy: false,
                    system: false,
                }],
            }],
        }
    }

    fn request(action: StorageAction, volume: bool) -> StorageRequest {
        StorageRequest {
            action,
            target: StorageTarget {
                drive_object: "/org/freedesktop/UDisks2/drives/usb1".into(),
                drive_generation: 9,
                block_object: volume.then(|| "/org/freedesktop/UDisks2/block_devices/sdb1".into()),
                block_generation: volume.then_some(5),
            },
        }
    }

    fn preflight(
        action: StorageAction,
        volume: bool,
    ) -> Result<StoragePreflight, StorageReviewError> {
        let first = fixture();
        let mut fresh = first.clone();
        fresh.sequence = 2;
        review_storage_preflight(&first, &fresh, 1000, request(action, volume), 1100)
    }

    #[test]
    fn operations_have_exact_separate_ids_and_conservative_risk() {
        assert_eq!(
            StorageAction::Mount.operation_id(),
            "operation:storage.filesystem.mount"
        );
        assert_eq!(
            StorageAction::Unmount.risk_floor(),
            StorageRisk::Destructive
        );
        assert_eq!(
            StorageAction::Eject.operation_id(),
            "operation:storage.drive.eject"
        );
        assert_eq!(
            StorageAction::PowerOff.operation_id(),
            "operation:storage.drive.power-off"
        );
        assert_eq!(
            StorageAction::Mount.risk_floor(),
            StorageRisk::SecuritySensitive
        );
    }

    #[test]
    fn fresh_complete_removable_mount_is_candidate_only() {
        let result = preflight(StorageAction::Mount, true);
        assert_eq!(
            result.as_ref().map(|r| r.risk_floor),
            Ok(StorageRisk::SecuritySensitive)
        );
    }

    #[test]
    fn rejects_stale_and_future_samples() {
        let mut snap = fixture();
        assert_eq!(
            snap.validate(1501),
            Err(StorageReviewError::StaleObservation)
        );
        assert_eq!(
            snap.validate(999),
            Err(StorageReviewError::StaleObservation)
        );
        snap.valid_for_ms = MAX_STORAGE_OBSERVATION_AGE_MS + 1;
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::StaleObservation)
        );
    }

    #[test]
    fn incomplete_or_oversized_topology_denied() {
        let mut snap = fixture();
        snap.complete_inventory = false;
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
        snap = fixture();
        snap.drives = vec![snap.drives[0].clone(); MAX_DRIVES + 1];
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
    }

    #[test]
    fn duplicate_block_paths_and_device_numbers_denied() {
        let mut snap = fixture();
        let duplicate = snap.drives[0].blocks[0].clone();
        snap.drives[0].blocks.push(duplicate);
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
        snap.drives[0].blocks[1].object_path = "/org/freedesktop/UDisks2/block_devices/sdb2".into();
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
    }

    #[test]
    fn rejects_unknown_bus_and_unsafe_paths() {
        let mut snap = fixture();
        snap.source.provider_unique_name = "org.freedesktop.UDisks2".into();
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
        snap = fixture();
        snap.drives[0].sysfs_path = "/sys/devices/../sda".into();
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
        snap = fixture();
        snap.drives[0].blocks[0].mount_points = vec!["/tmp/../root".into()];
        assert_eq!(
            snap.validate(1100),
            Err(StorageReviewError::InvalidSnapshot)
        );
    }

    #[test]
    fn no_foreign_principal_root_or_owner_swap() {
        let first = fixture();
        let mut fresh = first.clone();
        fresh.sequence = 2;
        assert!(matches!(
            review_storage_preflight(&first, &fresh, 0, request(StorageAction::Mount, true), 1100),
            Err(StorageReviewError::ChangedSourceOrPrincipal)
        ));
        assert!(matches!(
            review_storage_preflight(
                &first,
                &fresh,
                1001,
                request(StorageAction::Mount, true),
                1100
            ),
            Err(StorageReviewError::ChangedSourceOrPrincipal)
        ));
        fresh.source.provider_unique_name = ":1.43".into();
        assert!(matches!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Mount, true),
                1100
            ),
            Err(StorageReviewError::ChangedSourceOrPrincipal)
        ));
    }

    #[test]
    fn changed_topology_or_unrefreshed_observation_denied() {
        let first = fixture();
        let mut fresh = first.clone();
        assert!(matches!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Mount, true),
                1100
            ),
            Err(StorageReviewError::ChangedTopology)
        ));
        fresh.sequence = 2;
        fresh.drives[0].generation += 1;
        assert!(matches!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Mount, true),
                1100
            ),
            Err(StorageReviewError::ChangedTopology)
        ));
    }

    #[test]
    fn fixed_system_and_empty_media_cannot_be_touched() {
        for change in 0..3 {
            let first = fixture();
            let mut fresh = first.clone();
            fresh.sequence = 2;
            match change {
                0 => {
                    fresh.drives[0].removable = false;
                }
                1 => {
                    fresh.drives[0].blocks[0].system = true;
                }
                _ => {
                    fresh.drives[0].media_available = false;
                }
            }
            let approved = fresh.clone();
            let mut older = approved;
            older.sequence = 1;
            assert_eq!(
                review_storage_preflight(
                    &older,
                    &fresh,
                    1000,
                    request(StorageAction::Mount, true),
                    1100
                ),
                Err(StorageReviewError::UnsupportedOrProtectedMedia)
            );
        }
    }

    #[test]
    fn busy_or_mounted_sibling_blocks_destructive_drive_effect() {
        for blocked in 0..2 {
            let mut first = fixture();
            if blocked == 0 {
                first.drives[0].blocks[0].busy = true;
            } else {
                first.drives[0].blocks[0].mount_points = vec!["/run/media/u/usb".into()];
            }
            let mut fresh = first.clone();
            fresh.sequence = 2;
            assert_eq!(
                review_storage_preflight(
                    &first,
                    &fresh,
                    1000,
                    request(StorageAction::Eject, false),
                    1100
                ),
                Err(StorageReviewError::BusyOrMountedSibling)
            );
            assert_eq!(
                review_storage_preflight(
                    &first,
                    &fresh,
                    1000,
                    request(StorageAction::PowerOff, false),
                    1100
                ),
                Err(StorageReviewError::BusyOrMountedSibling)
            );
        }
    }

    #[test]
    fn mounted_and_busy_state_controls_mount_and_unmount() {
        let mut first = fixture();
        first.drives[0].blocks[0].mount_points = vec!["/run/media/u/usb".into()];
        let mut fresh = first.clone();
        fresh.sequence = 2;
        assert_eq!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Mount, true),
                1100
            ),
            Err(StorageReviewError::AlreadySatisfied)
        );
        assert!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Unmount, true),
                1100
            )
            .is_ok()
        );
        first.drives[0].blocks[0]
            .mount_points
            .push("/run/media/u/again".into());
        fresh = first.clone();
        fresh.sequence = 2;
        assert_eq!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Unmount, true),
                1100
            ),
            Err(StorageReviewError::AmbiguousMountState)
        );
    }

    #[test]
    fn eject_and_poweroff_are_not_interchangeable() {
        let mut first = fixture();
        first.drives[0].ejectable = false;
        let mut fresh = first.clone();
        fresh.sequence = 2;
        assert_eq!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::Eject, false),
                1100
            ),
            Err(StorageReviewError::UnsupportedMethod)
        );
        assert!(
            review_storage_preflight(
                &first,
                &fresh,
                1000,
                request(StorageAction::PowerOff, false),
                1100
            )
            .is_ok()
        );
    }

    #[test]
    fn mount_postcondition_requires_only_target_to_change_and_newer_sample() {
        let pre = preflight(StorageAction::Mount, true).unwrap_or_else(|_| unreachable!());
        let mut after = pre.live.clone();
        after.sequence += 1;
        after.drives[0].blocks[0]
            .mount_points
            .push("/run/media/u/usb".into());
        assert_eq!(
            review_storage_postcondition(&pre, &after, 1200),
            StoragePostcondition::ConsistentNativeState
        );
        after.source.topology_generation += 1;
        assert_eq!(
            review_storage_postcondition(&pre, &after, 1200),
            StoragePostcondition::Indeterminate
        );
        after.source.topology_generation -= 1;
        after.sequence = pre.live.sequence;
        assert_eq!(
            review_storage_postcondition(&pre, &after, 1200),
            StoragePostcondition::Indeterminate
        );
    }

    #[test]
    fn unmount_postcondition_requires_absent_mount_and_same_lineage() {
        let mut first = fixture();
        first.drives[0].blocks[0].mount_points = vec!["/run/media/u/usb".into()];
        let mut fresh = first.clone();
        fresh.sequence = 2;
        let pre = review_storage_preflight(
            &first,
            &fresh,
            1000,
            request(StorageAction::Unmount, true),
            1100,
        )
        .unwrap_or_else(|_| unreachable!());
        let mut after = fresh;
        after.sequence = 3;
        after.drives[0].blocks[0].mount_points.clear();
        assert_eq!(
            review_storage_postcondition(&pre, &after, 1200),
            StoragePostcondition::ConsistentNativeState
        );
        after.drives[0].blocks[0].busy = true;
        assert_eq!(
            review_storage_postcondition(&pre, &after, 1200),
            StoragePostcondition::Indeterminate
        );
    }

    #[test]
    fn no_fake_eject_poweroff_positive_or_replay_from_disappearance() {
        for action in [StorageAction::Eject, StorageAction::PowerOff] {
            let pre = preflight(action, false).unwrap_or_else(|_| unreachable!());
            let mut after = pre.live.clone();
            after.sequence = 3;
            after.drives.clear();
            assert_eq!(
                review_storage_postcondition(&pre, &after, 1200),
                StoragePostcondition::UnprovenPhysicalEffect
            );
        }
    }

    #[test]
    fn physical_sibling_mount_and_foreign_seat_block_eject() {
        let mut older = fixture();
        let mut sibling = older.drives[0].clone();
        sibling.object_path = "/org/freedesktop/UDisks2/drives/usb2".into();
        sibling.sysfs_path = "/sys/devices/pci0000:00/usb2".into();
        sibling.generation = 10;
        sibling.blocks[0].object_path = "/org/freedesktop/UDisks2/block_devices/sdc1".into();
        sibling.blocks[0].device_number = 3073;
        sibling.blocks[0].generation = 6;
        sibling.blocks[0].mount_points = vec!["/run/media/u/other".into()];
        older.drives.push(sibling);
        let mut fresh = older.clone();
        fresh.sequence = 2;
        for action in [StorageAction::Eject, StorageAction::PowerOff] {
            assert_eq!(
                review_storage_preflight(&older, &fresh, 1000, request(action, false), 1100),
                Err(StorageReviewError::BusyOrMountedSibling)
            );
        }
        older.drives[1].blocks[0].mount_points.clear();
        older.drives[1].seat_id = "seat1".into();
        fresh = older.clone();
        fresh.sequence = 2;
        assert_eq!(
            review_storage_preflight(
                &older,
                &fresh,
                1000,
                request(StorageAction::PowerOff, false),
                1100
            ),
            Err(StorageReviewError::UnsupportedOrProtectedMedia)
        );
    }

    #[test]
    fn target_path_and_generation_must_be_exact() {
        let first = fixture();
        let mut fresh = first.clone();
        fresh.sequence = 2;
        let mut wanted = request(StorageAction::Mount, true);
        wanted.target.block_generation = Some(6);
        assert_eq!(
            review_storage_preflight(&first, &fresh, 1000, wanted, 1100),
            Err(StorageReviewError::MissingOrReplacedTarget)
        );
        let mut wanted = request(StorageAction::Mount, true);
        wanted.target.drive_object = "/org/freedesktop/UDisks2/drives/unknown".into();
        assert_eq!(
            review_storage_preflight(&first, &fresh, 1000, wanted, 1100),
            Err(StorageReviewError::MissingOrReplacedTarget)
        );
    }
}
