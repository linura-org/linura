//! Independent *candidate* post-effect reads for S21-4 mount/unmount.
//!
//! This observer cannot verify a physical eject or power-off. An executor
//! reply is never inspected, and a matching native state is not a durable
//! Control verification disposition, original-session grant, or commit.

use linura_provider_sdk::ProviderError;

use crate::removable_storage::StorageAction;
use crate::removable_storage_kernel::{
    CandidateMountPostcondition, review_native_mount_transition,
};
use crate::removable_storage_native::{ScopedReadOnlyKernelDrive, observe_scoped_kernel_drive};

/// Correlate two native/kernel snapshots with the exact same physical
/// insertion witness, logind owner and selected target before delegating
/// to the strict mount-only dual-source postcondition checker.
#[must_use]
pub fn review_correlated_mount_outcome(
    action: StorageAction,
    target_block: &str,
    before: &ScopedReadOnlyKernelDrive,
    after: &ScopedReadOnlyKernelDrive,
) -> CandidateMountPostcondition {
    if !matches!(action, StorageAction::Mount | StorageAction::Unmount) {
        return CandidateMountPostcondition::NotApplicable;
    }
    if before.session != after.session
        || before.physical != after.physical
        || before.physical.selected_drive != after.physical.selected_drive
        || before.physical.blocks.is_empty()
        || before.inventory.unique_owner != after.inventory.unique_owner
        || !before
            .physical
            .blocks
            .iter()
            .any(|b| b.block_path == target_block)
        || !after
            .physical
            .blocks
            .iter()
            .any(|b| b.block_path == target_block)
    {
        return CandidateMountPostcondition::Indeterminate;
    }
    review_native_mount_transition(
        action,
        target_block,
        &before.session.seat_id,
        &before.inventory,
        &before.kernel_mount,
        &after.inventory,
        &after.kernel_mount,
    )
}

/// Read a fresh native scoped drive and corroborate a prospective mount or
/// unmount effect without inspecting executor results. This is a *candidate*
/// review: Control must separately prove before/after chronology and the
/// actual original caller's mount namespace, busy writers and a sealed plan.
///
/// Never turn a matching candidate into privileged authorization or a
/// committed transaction; the independent production verifier and durable
/// reconciliation still have to consume qualified provenance.
pub fn observe_candidate_mount_outcome(
    action: StorageAction,
    target_block: &str,
    before: &ScopedReadOnlyKernelDrive,
) -> Result<CandidateMountPostcondition, ProviderError> {
    if !matches!(action, StorageAction::Mount | StorageAction::Unmount) {
        return Ok(CandidateMountPostcondition::NotApplicable);
    }
    let after = observe_scoped_kernel_drive(
        &before.session.session_id,
        before.session.uid,
        &before.physical.selected_drive,
    )?;
    Ok(review_correlated_mount_outcome(
        action,
        target_block,
        before,
        &after,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::removable_storage_kernel::KernelMountView;
    use crate::removable_storage_kernel_device::{KernelBlockIdentity, KernelDriveGroupEvidence};
    use crate::removable_storage_native::{
        ReadOnlyBlock, ReadOnlyDrive, ReadOnlySessionScope, ReadOnlyStorageInventory,
    };

    fn before() -> ScopedReadOnlyKernelDrive {
        let drive = "/org/freedesktop/UDisks2/drives/usb1";
        let block = "/org/freedesktop/UDisks2/block_devices/sdb1";
        ScopedReadOnlyKernelDrive {
            session: ReadOnlySessionScope {
                logind_unique_owner: ":1.3".into(),
                boot_id: "d3cd25af-38f2-4829-b42d-ef2bd35af042".into(),
                session_id: "c1".into(),
                seat_id: "seat0".into(),
                uid: 1000,
            },
            inventory: ReadOnlyStorageInventory {
                unique_owner: ":1.4".into(),
                drives: vec![ReadOnlyDrive {
                    path: drive.into(),
                    removable: true,
                    media_available: true,
                    ejectable: true,
                    can_power_off: true,
                    seat: "seat0".into(),
                    connection_bus: "usb".into(),
                    sibling_id: "usb-group-1".into(),
                }],
                blocks: vec![ReadOnlyBlock {
                    path: block.into(),
                    drive: Some(drive.into()),
                    device_number: 2049,
                    hint_system: false,
                    hint_ignore: false,
                    crypto_backing_device: None,
                    mdraid: None,
                    mdraid_member: None,
                    partition_table: None,
                    mount_points: Vec::new(),
                    has_filesystem: true,
                    partition_number: None,
                }],
            },
            kernel_mount: KernelMountView {
                mount_points_by_device: BTreeMap::new(),
            },
            physical: KernelDriveGroupEvidence {
                selected_drive: drive.into(),
                sibling_id: "usb-group-1".into(),
                blocks: vec![KernelBlockIdentity {
                    block_path: block.into(),
                    device_number: 2049,
                    disk_sequence: 3,
                    canonical_sysfs: PathBuf::from("/sys/devices/pci/block/sdb/sdb1"),
                    physical_parent: PathBuf::from("/sys/devices/pci/block/sdb"),
                    mounted_as_root: false,
                    swap_in_use: false,
                    has_holders: false,
                }],
            },
        }
    }

    #[test]
    fn mount_requires_same_physical_group_and_independent_kernel_mount() {
        let prior = before();
        let mut after = prior.clone();
        let target = prior.inventory.blocks[0].path.as_str();
        after.inventory.blocks[0].mount_points = vec!["/run/media/sample".into()];
        after.kernel_mount.mount_points_by_device.insert(
            2049,
            std::collections::BTreeSet::from(["/run/media/sample".into()]),
        );
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Mount, target, &prior, &after),
            CandidateMountPostcondition::ConsistentCandidate
        );
        let mut replaced = after.clone();
        replaced.physical.blocks[0].disk_sequence += 1;
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Mount, target, &prior, &replaced),
            CandidateMountPostcondition::Indeterminate
        );
        replaced = after.clone();
        replaced.session.seat_id = "seat1".into();
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Mount, target, &prior, &replaced),
            CandidateMountPostcondition::Indeterminate
        );
        replaced = after.clone();
        replaced.inventory.unique_owner = ":1.55".into();
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Mount, target, &prior, &replaced),
            CandidateMountPostcondition::Indeterminate
        );
        replaced = after;
        replaced.kernel_mount.mount_points_by_device.clear();
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Mount, target, &prior, &replaced),
            CandidateMountPostcondition::Indeterminate
        );
        assert_eq!(
            review_correlated_mount_outcome(StorageAction::Eject, target, &prior, &prior,),
            CandidateMountPostcondition::NotApplicable
        );
    }
}
