//! Independent read-only kernel mount namespace evidence for S21-4.
//!
//! Kernel mountinfo can contradict a UDisks2 mount report. A match is
//! *candidate* evidence only: it is relative to this process's mount
//! namespace, not the caller's, does not establish open-file/busy state and
//! is NEVER an authorization, execution or physical-removal permit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;

use linura_provider_sdk::ProviderError;

use crate::removable_storage_native::ReadOnlyStorageInventory;

const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const MAX_MOUNTINFO_ENTRIES: usize = 4096;
const MAX_MOUNT_PATH: usize = 4096;

/// The sampled view belongs exclusively to the observing process's mount
/// namespace. It cannot attest another subject's effective mount namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelMountView {
    pub mount_points_by_device: BTreeMap<u64, BTreeSet<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelMountDecision {
    /// All UDisks2 mount states agreed with the sampled local kernel namespace.
    /// Does *not* qualify any mutation or prove the actual Polkit subject.
    CandidateConsistent,
    /// Contradictory or incomplete evidence requires denying the effect.
    Unqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelMountReview {
    pub decision: KernelMountDecision,
    pub checked_filesystems: usize,
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.into())
}

/// Decode only the octal escapes admitted by the mountinfo pathname format.
/// Literal backslashes and unrecognized encodings are rejected.
fn decode_mount_path(value: &str) -> Result<String, ProviderError> {
    if value.is_empty() || value.len() > MAX_MOUNT_PATH * 4 {
        return Err(invalid("mountinfo path length is invalid"));
    }
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte != b'\\' {
            out.push(byte);
            at += 1;
            continue;
        }
        if bytes.len().saturating_sub(at) < 4 {
            return Err(invalid("mountinfo escape is truncated"));
        }
        let escape = &bytes[at + 1..at + 4];
        let decoded = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(invalid("mountinfo contains unsupported escape")),
        };
        out.push(decoded);
        at += 4;
    }
    let path = String::from_utf8(out).map_err(|_| invalid("mountinfo path is not UTF-8"))?;
    if !path.starts_with('/')
        || path.len() > MAX_MOUNT_PATH
        || path.bytes().any(|b| b == 0 || b.is_ascii_control())
        || path.split('/').any(|part| part == "." || part == "..")
    {
        return Err(invalid(
            "mountinfo path is not a bounded canonical absolute path",
        ));
    }
    Ok(path)
}

/// Linux's major/minor encoding for dev_t as used by st_rdev. Checked
/// arithmetic ensures oversized or malformed mountinfo numbers fail closed.
fn linux_device_number(major: &str, minor: &str) -> Result<u64, ProviderError> {
    let parse = |value: &str| -> Result<u64, ProviderError> {
        if value.is_empty() || value.len() > 7 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("mountinfo device number is malformed"));
        }
        let number = value
            .parse::<u64>()
            .map_err(|_| invalid("mountinfo device number overflows"))?;
        if number > 0x000f_ffff {
            return Err(invalid("mountinfo device number is unsupported"));
        }
        Ok(number)
    };
    let major = parse(major)?;
    let minor = parse(minor)?;
    Ok(
        ((major & 0xfff) << 8)
            | (minor & 0xff)
            | ((major & !0xfff) << 32)
            | ((minor & !0xff) << 12),
    )
}

/// Parse only bounded native mount records; a malformed line cannot silently
/// drop evidence about a potentially mounted target. Mount IDs can change
/// between samples and are not used as authority identities.
pub fn parse_mountinfo(source: &str) -> Result<KernelMountView, ProviderError> {
    if source.len() as u64 > MAX_MOUNTINFO_BYTES {
        return Err(invalid("mountinfo exceeds its bounded read budget"));
    }
    let mut mount_points_by_device: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut entries = 0;
    for line in source.lines() {
        entries += 1;
        if entries > MAX_MOUNTINFO_ENTRIES {
            return Err(invalid("mountinfo entry count exceeds the bound"));
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 || !fields.iter().any(|field| *field == "-") {
            return Err(invalid("mountinfo record has invalid structure"));
        }
        let (major, minor) = fields[2]
            .split_once(':')
            .ok_or_else(|| invalid("mountinfo device field lacks a separator"))?;
        let device = linux_device_number(major, minor)?;
        let mount_path = decode_mount_path(fields[4])?;
        mount_points_by_device
            .entry(device)
            .or_default()
            .insert(mount_path);
    }
    Ok(KernelMountView {
        mount_points_by_device,
    })
}

pub fn sample_kernel_mountinfo() -> Result<KernelMountView, ProviderError> {
    let file = File::open("/proc/self/mountinfo")
        .map_err(|_| ProviderError::Unavailable("native mountinfo unavailable".into()))?;
    let mut bytes = Vec::new();
    file.take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::Unavailable("cannot read kernel mount state".into()))?;
    if bytes.len() as u64 > MAX_MOUNTINFO_BYTES {
        return Err(invalid("native mountinfo exceeded its byte budget"));
    }
    let source = String::from_utf8(bytes).map_err(|_| invalid("mountinfo is not UTF-8"))?;
    parse_mountinfo(&source)
}

/// Even a matching observation is not a safety permit. Native application
/// must separately prove mount namespace equality with the actual target,
/// protected system-media lineage and open-file/busy state, then independently
/// verify after an authorized effect. This check only detects contradictions.
pub fn review_udisks_kernel_mount_state(
    inventory: &ReadOnlyStorageInventory,
    kernel: &KernelMountView,
) -> KernelMountReview {
    let mut checked = 0;
    for block in &inventory.blocks {
        if !block.has_filesystem {
            if !block.mount_points.is_empty() {
                return KernelMountReview {
                    decision: KernelMountDecision::Unqualified,
                    checked_filesystems: checked,
                };
            }
            continue;
        }
        checked += 1;
        let reported: BTreeSet<_> = block.mount_points.iter().cloned().collect();
        let native = kernel
            .mount_points_by_device
            .get(&block.device_number)
            .cloned()
            .unwrap_or_default();
        // A superset also fails: another bind mount could remain after
        // the primary UDisks2 mount disappears.
        if reported != native {
            return KernelMountReview {
                decision: KernelMountDecision::Unqualified,
                checked_filesystems: checked,
            };
        }
    }
    KernelMountReview {
        decision: KernelMountDecision::CandidateConsistent,
        checked_filesystems: checked,
    }
}

/// A strictly non-authorizing, dual-source postcondition review. The
/// executor reply is not an input and cannot turn indeterminate into success.
/// Both native snapshots and independently sampled kernel mount namespaces
/// are required; this function alone cannot establish their provenance,
/// physical device generation, the calling principal or chronological order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateMountPostcondition {
    ConsistentCandidate,
    Indeterminate,
    NotApplicable,
}

pub fn review_native_mount_transition(
    action: crate::removable_storage::StorageAction,
    target_block: &str,
    expected_seat: &str,
    before: &ReadOnlyStorageInventory,
    before_kernel: &KernelMountView,
    after: &ReadOnlyStorageInventory,
    after_kernel: &KernelMountView,
) -> CandidateMountPostcondition {
    use crate::removable_storage::StorageAction;
    if !matches!(action, StorageAction::Mount | StorageAction::Unmount) {
        return CandidateMountPostcondition::NotApplicable;
    }
    if before.unique_owner != after.unique_owner
        || before.drives != after.drives
        || before.blocks.len() != after.blocks.len()
        || expected_seat.is_empty()
        || review_udisks_kernel_mount_state(before, before_kernel).decision
            != KernelMountDecision::CandidateConsistent
        || review_udisks_kernel_mount_state(after, after_kernel).decision
            != KernelMountDecision::CandidateConsistent
    {
        return CandidateMountPostcondition::Indeterminate;
    }
    let mut normalized = after.clone();
    let Some(original_target) = before
        .blocks
        .iter()
        .find(|block| block.path == target_block)
    else {
        return CandidateMountPostcondition::Indeterminate;
    };
    if !original_target.has_filesystem
        || original_target.hint_system
        || original_target.hint_ignore
        || original_target.crypto_backing_device.is_some()
        || original_target.mdraid.is_some()
        || original_target.mdraid_member.is_some()
    {
        return CandidateMountPostcondition::Indeterminate;
    }
    let Some(drive_path) = original_target.drive.as_deref() else {
        return CandidateMountPostcondition::Indeterminate;
    };
    let Some(drive) = before.drives.iter().find(|drive| drive.path == drive_path) else {
        return CandidateMountPostcondition::Indeterminate;
    };
    if !drive.removable
        || !drive.media_available
        || drive.connection_bus != "usb"
        || drive.seat != expected_seat
    {
        return CandidateMountPostcondition::Indeterminate;
    }
    let Some(observed_target) = normalized
        .blocks
        .iter_mut()
        .find(|block| block.path == target_block)
    else {
        return CandidateMountPostcondition::Indeterminate;
    };
    let desired = match action {
        StorageAction::Mount => {
            original_target.mount_points.is_empty() && observed_target.mount_points.len() == 1
        }
        StorageAction::Unmount => {
            original_target.mount_points.len() == 1 && observed_target.mount_points.is_empty()
        }
        StorageAction::Eject | StorageAction::PowerOff => false,
    };
    if !desired {
        return CandidateMountPostcondition::Indeterminate;
    }
    observed_target
        .mount_points
        .clone_from(&original_target.mount_points);
    // Other volumes, drives, identities and mounted siblings must not change
    // as a side effect, even if the requested target's mount state matches.
    if normalized != *before {
        return CandidateMountPostcondition::Indeterminate;
    }
    CandidateMountPostcondition::ConsistentCandidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::removable_storage_native::{ReadOnlyBlock, ReadOnlyStorageInventory};

    fn filesystem(mount_points: &[&str]) -> ReadOnlyStorageInventory {
        ReadOnlyStorageInventory {
            unique_owner: ":1.42".into(),
            drives: Vec::new(),
            blocks: vec![ReadOnlyBlock {
                path: "/org/freedesktop/UDisks2/block_devices/sdb1".into(),
                drive: None,
                device_number: 2049,
                hint_system: false,
                hint_ignore: false,
                crypto_backing_device: None,
                mdraid: None,
                mdraid_member: None,
                partition_table: None,
                mount_points: mount_points.iter().map(|s| (*s).into()).collect(),
                has_filesystem: true,
                partition_number: None,
            }],
        }
    }

    #[test]
    fn parses_linux_device_and_canonical_mountinfo_paths() {
        let kernel = parse_mountinfo(
            "34 25 8:1 / /run/media/user/usb\\040disk rw,nosuid - vfat /dev/sdb1 rw\n",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            kernel
                .mount_points_by_device
                .get(&2049)
                .unwrap_or_else(|| unreachable!("missing test device")),
            &BTreeSet::from(["/run/media/user/usb disk".into()])
        );
        assert_eq!(linux_device_number("8", "1"), Ok(2049));
        assert!(linux_device_number("1048576", "0").is_err());
    }

    #[test]
    fn rejects_truncated_traversal_and_malformed_mount_records() {
        for line in [
            "34 25 8:1 / /tmp/../root rw - ext4 /dev/sdb1 rw\n",
            "34 25 8:1 / /tmp/\\777bad rw - ext4 /dev/sdb1 rw\n",
            "34 25 8:1 / relative rw - ext4 /dev/sdb1 rw\n",
            "34 25 8:1 / /tmp/x rw ext4 /dev/sdb1 rw\n",
            "34 25 8:x / /tmp/x rw - ext4 /dev/sdb1 rw\n",
            "34 25 8:1 / /tmp/\\040\\012 rw - ext4 /dev/sdb1 rw\n",
        ] {
            assert!(parse_mountinfo(line).is_err(), "{line}");
        }
    }

    #[test]
    fn unmount_is_not_consistent_when_kernel_still_has_a_mount() {
        let kernel = parse_mountinfo("34 25 8:1 / /run/media/usb rw - vfat /dev/sdb1 rw\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            review_udisks_kernel_mount_state(&filesystem(&[]), &kernel).decision,
            KernelMountDecision::Unqualified
        );
        assert_eq!(
            review_udisks_kernel_mount_state(&filesystem(&["/run/media/usb"]), &kernel).decision,
            KernelMountDecision::CandidateConsistent
        );
    }

    #[test]
    fn bind_mounted_sibling_path_or_wrong_device_never_qualifies() {
        let kernel = parse_mountinfo(
            "34 25 8:1 / /run/media/usb rw - vfat /dev/sdb1 rw\n\
             35 25 8:1 / /run/media/usb-mirror rw - vfat /dev/sdb1 rw\n",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            review_udisks_kernel_mount_state(&filesystem(&["/run/media/usb"]), &kernel).decision,
            KernelMountDecision::Unqualified
        );
        let kernel = parse_mountinfo("34 25 8:2 / /run/media/usb rw - vfat /dev/sdb2 rw\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            review_udisks_kernel_mount_state(&filesystem(&["/run/media/usb"]), &kernel).decision,
            KernelMountDecision::Unqualified
        );
    }

    #[test]
    fn postcondition_requires_both_native_and_kernel_state_to_agree() {
        use crate::removable_storage::StorageAction;
        use crate::removable_storage_native::ReadOnlyDrive;
        let mut initial = filesystem(&[]);
        initial.drives.push(ReadOnlyDrive {
            path: "/org/freedesktop/UDisks2/drives/usb".into(),
            removable: true,
            media_available: true,
            ejectable: true,
            can_power_off: true,
            seat: "seat0".into(),
            connection_bus: "usb".into(),
            sibling_id: "group-1".into(),
        });
        initial.blocks[0].drive = Some(initial.drives[0].path.clone());
        let mut next = initial.clone();
        next.blocks[0].mount_points = vec!["/run/media/user/usb".into()];
        let empty = parse_mountinfo("").unwrap_or_else(|error| unreachable!("{error}"));
        let mounted = parse_mountinfo("34 25 8:1 / /run/media/user/usb rw - ext4 /dev/sdb1 rw\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let target = initial.blocks[0].path.as_str();
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat0",
                &initial,
                &empty,
                &next,
                &mounted
            ),
            CandidateMountPostcondition::ConsistentCandidate
        );
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Unmount,
                target,
                "seat0",
                &next,
                &mounted,
                &initial,
                &empty
            ),
            CandidateMountPostcondition::ConsistentCandidate
        );
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat0",
                &initial,
                &empty,
                &next,
                &empty
            ),
            CandidateMountPostcondition::Indeterminate
        );
        assert_eq!(
            review_native_mount_transition(
                StorageAction::PowerOff,
                target,
                "seat0",
                &initial,
                &empty,
                &next,
                &mounted
            ),
            CandidateMountPostcondition::NotApplicable
        );
        let mut changed = next.clone();
        changed.unique_owner = ":1.99".into();
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat0",
                &initial,
                &empty,
                &changed,
                &mounted
            ),
            CandidateMountPostcondition::Indeterminate
        );
        let mut changed = next.clone();
        changed.blocks[0].device_number = 4097;
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat0",
                &initial,
                &empty,
                &changed,
                &mounted
            ),
            CandidateMountPostcondition::Indeterminate
        );
    }

    #[test]
    fn postcondition_rejects_foreign_seat_and_collateral_mount_changes() {
        use crate::removable_storage::StorageAction;
        use crate::removable_storage_native::ReadOnlyDrive;
        let mut initial = filesystem(&[]);
        initial.drives.push(ReadOnlyDrive {
            path: "/org/freedesktop/UDisks2/drives/usb".into(),
            removable: true,
            media_available: true,
            ejectable: true,
            can_power_off: true,
            seat: "seat0".into(),
            connection_bus: "usb".into(),
            sibling_id: "group-1".into(),
        });
        initial.blocks[0].drive = Some(initial.drives[0].path.clone());
        let mut next = initial.clone();
        next.blocks[0].mount_points = vec!["/run/media/user/usb".into()];
        let initial_kernel = parse_mountinfo("").unwrap_or_else(|error| unreachable!("{error}"));
        let next_kernel =
            parse_mountinfo("34 25 8:1 / /run/media/user/usb rw - ext4 /dev/sdb1 rw\n")
                .unwrap_or_else(|error| unreachable!("{error}"));
        let target = initial.blocks[0].path.as_str();
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat1",
                &initial,
                &initial_kernel,
                &next,
                &next_kernel
            ),
            CandidateMountPostcondition::Indeterminate
        );
        next.drives[0].sibling_id = "group-replacement".into();
        assert_eq!(
            review_native_mount_transition(
                StorageAction::Mount,
                target,
                "seat0",
                &initial,
                &initial_kernel,
                &next,
                &next_kernel
            ),
            CandidateMountPostcondition::Indeterminate
        );
    }

    #[test]
    fn oversized_or_unknown_kernel_data_fails_closed() {
        assert!(parse_mountinfo(&"x".repeat((MAX_MOUNTINFO_BYTES + 1) as usize)).is_err());
        assert!(parse_mountinfo("malformed").is_err());
    }
}
