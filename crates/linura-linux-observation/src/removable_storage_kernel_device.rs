//! Kernel-only, read-only identity and safety evidence for physical USB groups.
//!
//! None of these witnesses is an authorization, Polkit subject, or generation
//! lease: diskseq and sysfs can be replaced after the read. The executor must
//! re-prove physical identity inside a trusted, prepared single-use dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use linura_provider_sdk::ProviderError;

use crate::removable_storage_kernel::KernelMountView;
use crate::removable_storage_native::{ReadOnlyBlock, ReadOnlyStorageInventory};

const MAX_SYSFS_FIELD_BYTES: u64 = 128;
const MAX_SWAP_BYTES: u64 = 64 * 1024;
const MAX_SWAP_ENTRIES: usize = 64;
const MAX_CHILDREN: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelBlockIdentity {
    pub block_path: String,
    pub device_number: u64,
    /// Kernel disk sequence: detecting a reused dev_t requires comparing it
    /// across separately trusted observations and immediately before dispatch.
    pub disk_sequence: u64,
    pub canonical_sysfs: PathBuf,
    pub physical_parent: PathBuf,
    pub mounted_as_root: bool,
    pub swap_in_use: bool,
    pub has_holders: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelDriveGroupEvidence {
    pub selected_drive: String,
    pub sibling_id: String,
    pub blocks: Vec<KernelBlockIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDeviceReviewError {
    MissingOrReplaced,
    InvalidOrVirtualDevice,
    IncompletePhysicalChildren,
    UnsafeSystemUse,
    WrongSeatOrGroup,
}

fn invalid(reason: &str) -> ProviderError {
    ProviderError::InvalidState(reason.into())
}

fn read_bounded(path: &Path, limit: u64) -> Result<String, ProviderError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| invalid("required kernel evidence is unavailable"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("kernel evidence cannot be read"))?;
    if bytes.len() as u64 > limit {
        return Err(invalid("kernel evidence exceeds its read limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("kernel evidence is not UTF-8"))
}

fn number(raw: &str) -> Result<u64, ProviderError> {
    let raw = raw.trim_end_matches('\n');
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("kernel device counter is malformed"));
    }
    raw.parse::<u64>()
        .map_err(|_| invalid("kernel device counter overflows"))
}

fn decode_device_number(raw: u64) -> Result<(u32, u32), ProviderError> {
    // The modern Linux dev_t encoding reserves 20 bits each for major and
    // minor. Mask the upper minor field explicitly: otherwise a major >= 4096
    // leaks into minor bit 32 when decoding the 64-bit representation.
    let major = ((raw >> 8) & 0x0000_0fff) | ((raw >> 32) & 0x000f_f000);
    let minor = (raw & 0x0000_00ff) | ((raw >> 12) & 0x000f_ff00);
    if raw == 0 || encoded_device_number(major as u32, minor as u32) != raw {
        return Err(invalid("unsupported kernel block device number"));
    }
    Ok((major as u32, minor as u32))
}

fn encoded_device_number(major: u32, minor: u32) -> u64 {
    let major = u64::from(major);
    let minor = u64::from(minor);
    ((major & 0xfff) << 8) | (minor & 0xff) | ((major & !0xfff) << 32) | ((minor & !0xff) << 12)
}

pub(crate) fn sysfs_device(path: &Path) -> Result<u64, ProviderError> {
    let device = read_bounded(&path.join("dev"), MAX_SYSFS_FIELD_BYTES)?;
    let (major, minor) = device
        .trim_end_matches('\n')
        .split_once(':')
        .ok_or_else(|| invalid("kernel sysfs device number lacks separator"))?;
    let major = number(major)?;
    let minor = number(minor)?;
    if major > 0x000f_ffff || minor > 0x000f_ffff {
        return Err(invalid("kernel sysfs device number out of range"));
    }
    Ok(encoded_device_number(major as u32, minor as u32))
}

fn canonical_sysfs(device: u64) -> Result<PathBuf, ProviderError> {
    let (major, minor) = decode_device_number(device)?;
    let link = format!("/sys/dev/block/{major}:{minor}");
    let canonical = fs::canonicalize(link)
        .map_err(|_| invalid("kernel block device has no canonical sysfs identity"))?;
    // USB physical devices must not be virtual/dm or an out-of-tree sysfs
    // alias. No user-selected path is ever consulted.
    if !canonical.starts_with("/sys/devices/")
        || canonical.starts_with("/sys/devices/virtual/")
        || sysfs_device(&canonical)? != device
    {
        return Err(invalid("kernel block device is virtual or mismatched"));
    }
    Ok(canonical)
}

fn has_entries(path: &Path) -> Result<bool, ProviderError> {
    let mut entries =
        fs::read_dir(path).map_err(|_| invalid("kernel holder inventory is not readable"))?;
    entries
        .next()
        .transpose()
        .map(|value| value.is_some())
        .map_err(|_| invalid("kernel holder inventory is incomplete"))
}

fn sysfs_children(physical: &Path) -> Result<BTreeSet<u64>, ProviderError> {
    let mut actual = BTreeSet::from([sysfs_device(physical)?]);
    let mut visited = 0;
    for entry in
        fs::read_dir(physical).map_err(|_| invalid("kernel partition inventory is unavailable"))?
    {
        visited += 1;
        if visited > MAX_CHILDREN {
            return Err(invalid("kernel partition inventory exceeds its bound"));
        }
        let path = entry
            .map_err(|_| invalid("kernel partition enumeration failed"))?
            .path();
        if path.is_dir() && path.join("partition").is_file() {
            let identity = sysfs_device(&path)?;
            if !actual.insert(identity) {
                return Err(invalid("kernel inventory has duplicate partition identity"));
            }
        }
    }
    Ok(actual)
}

fn swaps_in_use() -> Result<BTreeSet<u64>, ProviderError> {
    let raw = read_bounded(Path::new("/proc/swaps"), MAX_SWAP_BYTES)?;
    parse_swaps(&raw, |path| {
        let meta =
            fs::metadata(path).map_err(|_| invalid("active swap path cannot be resolved"))?;
        Ok(if meta.file_type().is_block_device() {
            meta.rdev()
        } else {
            meta.dev()
        })
    })
}

fn parse_swaps<F>(raw: &str, mut device_for: F) -> Result<BTreeSet<u64>, ProviderError>
where
    F: FnMut(&Path) -> Result<u64, ProviderError>,
{
    let mut lines = raw.lines();
    let Some(header) = lines.next() else {
        return Err(invalid("kernel swap inventory has no header"));
    };
    if !header.starts_with("Filename") {
        return Err(invalid("kernel swap inventory header is malformed"));
    }
    let mut active = BTreeSet::new();
    for (index, line) in lines.enumerate() {
        if index >= MAX_SWAP_ENTRIES {
            return Err(invalid("kernel swap inventory is unbounded"));
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 || !fields[0].starts_with('/') || fields[0].len() > 4096 {
            return Err(invalid("kernel swap record cannot be authenticated"));
        }
        let device = device_for(Path::new(fields[0]))?;
        if device == 0 {
            return Err(invalid("kernel swap points to unknown device"));
        }
        active.insert(device);
    }
    Ok(active)
}

/// Observe one physical sibling group, not all host disks. A successful read
/// is candidate corroboration only. Reject virtual, held, swapped or root-use
/// devices and missing USB partitions rather than accepting UDisks2's hint.
pub fn inspect_kernel_group(
    inventory: &ReadOnlyStorageInventory,
    mount: &KernelMountView,
    selected_drive: &str,
    expected_seat: &str,
) -> Result<KernelDriveGroupEvidence, ProviderError> {
    let drive = inventory
        .drives
        .iter()
        .find(|d| d.path == selected_drive)
        .ok_or_else(|| invalid("selected native drive is missing"))?;
    if expected_seat.is_empty()
        || drive.seat != expected_seat
        || drive.connection_bus != "usb"
        || !drive.removable
        || !drive.media_available
        || drive.sibling_id.is_empty()
    {
        return Err(invalid("physical drive and seat group are not qualified"));
    }
    let siblings: BTreeSet<_> = inventory
        .drives
        .iter()
        .filter(|d| d.sibling_id == drive.sibling_id)
        .map(|d| d.path.as_str())
        .collect();
    if siblings.is_empty()
        || inventory
            .drives
            .iter()
            .filter(|d| siblings.contains(d.path.as_str()))
            .any(|d| {
                d.seat != expected_seat
                    || d.connection_bus != "usb"
                    || !d.removable
                    || !d.media_available
            })
    {
        return Err(invalid(
            "physical sibling group crosses an unsupported seat",
        ));
    }
    let selected: Vec<&ReadOnlyBlock> = inventory
        .blocks
        .iter()
        .filter(|b| b.drive.as_deref().is_some_and(|d| siblings.contains(d)))
        .collect();
    if selected.is_empty()
        || siblings.iter().any(|drive_path| {
            !selected
                .iter()
                .any(|b| b.drive.as_deref() == Some(*drive_path))
        })
    {
        return Err(invalid("physical sibling block inventory is incomplete"));
    }
    let swap = swaps_in_use()?;
    let mut blocks = Vec::new();
    let mut children: BTreeMap<PathBuf, BTreeSet<u64>> = BTreeMap::new();
    for block in selected {
        if block.device_number == 0
            || block.hint_system
            || block.hint_ignore
            || block.crypto_backing_device.is_some()
            || block.mdraid.is_some()
            || block.mdraid_member.is_some()
        {
            return Err(invalid(
                "physical block is system or backed by another device",
            ));
        }
        let sysfs = canonical_sysfs(block.device_number)?;
        let physical = if block.partition_number.is_some() {
            sysfs
                .parent()
                .ok_or_else(|| invalid("partition has no sysfs parent"))?
                .to_path_buf()
        } else {
            sysfs.clone()
        };
        if block.partition_number.is_some() != block.partition_table.is_some()
            || sysfs_device(&physical)? == 0
        {
            return Err(invalid("partition sysfs lineage is incomplete"));
        }
        let disk_sequence = number(&read_bounded(
            &physical.join("diskseq"),
            MAX_SYSFS_FIELD_BYTES,
        )?)?;
        if disk_sequence == 0
            || has_entries(&sysfs.join("holders"))?
            || has_entries(&physical.join("holders"))?
            || has_entries(&physical.join("slaves"))?
        {
            return Err(invalid(
                "kernel device is held, stacked or lacks a generation",
            ));
        }
        if let Some(table) = &block.partition_table {
            let parent = inventory
                .blocks
                .iter()
                .find(|b| &b.path == table)
                .ok_or_else(|| invalid("UDisks2 partition parent is missing"))?;
            if canonical_sysfs(parent.device_number)? != physical || parent.drive != block.drive {
                return Err(invalid("kernel and UDisks2 partition ancestry disagree"));
            }
        }
        let mounted_as_root = mount
            .mount_points_by_device
            .get(&block.device_number)
            .is_some_and(|points| points.contains("/"));
        let swap_in_use = swap.contains(&block.device_number);
        if mounted_as_root || swap_in_use {
            return Err(invalid("kernel root or swap device cannot be managed"));
        }
        children
            .entry(physical.clone())
            .or_default()
            .insert(block.device_number);
        blocks.push(KernelBlockIdentity {
            block_path: block.path.clone(),
            device_number: block.device_number,
            disk_sequence,
            canonical_sysfs: sysfs,
            physical_parent: physical,
            mounted_as_root,
            swap_in_use,
            has_holders: false,
        });
    }
    for (physical, listed) in children {
        if listed != sysfs_children(&physical)? {
            return Err(invalid(
                "UDisks2 omitted a kernel partition or sibling block",
            ));
        }
    }
    // Independently check the complete kernel USB physical-device group,
    // not only the provider's SiblingId and selected partition list.
    crate::removable_storage_usb_group::review_whole_usb_device(&blocks)?;
    blocks.sort_by(|a, b| a.block_path.cmp(&b.block_path));
    Ok(KernelDriveGroupEvidence {
        selected_drive: selected_drive.into(),
        sibling_id: drive.sibling_id.clone(),
        blocks,
    })
}

/// Two freshly sampled kernel group witnesses must match exactly. A match
/// still doesn't prove that the underlying device cannot be replaced after
/// verification or that its actual calling subject has granted permission.
pub fn review_stable_kernel_group(
    first: &KernelDriveGroupEvidence,
    second: &KernelDriveGroupEvidence,
) -> Result<(), ProviderError> {
    if first != second || first.blocks.is_empty() {
        return Err(invalid(
            "kernel device instance or physical ancestry changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_dev_t_conversion_is_canonical_and_bounded() {
        for (major, minor) in [
            (8, 1),
            (259, 17),
            (0xfff, 0xff),
            (0x1fff, 0x100),
            (0xf_ffff, 0xf_ffff),
        ] {
            let raw = encoded_device_number(major, minor);
            assert_eq!(decode_device_number(raw), Ok((major, minor)));
        }
        assert!(decode_device_number(0).is_err());
        assert!(decode_device_number(u64::MAX).is_err());
    }

    #[test]
    fn bounded_kernel_counter_rejects_negative_or_non_numeric() {
        assert_eq!(number("451\n"), Ok(451));
        assert!(number("0x0").is_err());
        assert!(number("-5").is_err());
        assert!(number("451junk").is_err());
    }

    #[test]
    fn swap_record_resolves_block_or_swapfile_devices() {
        let raw = "Filename Type Size Used Priority\n/dev/sdb1 partition 1024 0 -2\n";
        let seen = parse_swaps(raw, |p| {
            assert_eq!(p, Path::new("/dev/sdb1"));
            Ok(2049)
        })
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(seen, BTreeSet::from([2049]));
        assert!(parse_swaps("bad header\n", |_| Ok(2049)).is_err());
        assert!(
            parse_swaps(
                "Filename Type Size Used Priority\nrelative file 1 0 -2",
                |_| Ok(2049)
            )
            .is_err()
        );
    }

    #[test]
    fn a_kernel_identity_change_fails_closed() {
        let first = KernelDriveGroupEvidence {
            selected_drive: "/org/freedesktop/UDisks2/drives/usb".into(),
            sibling_id: "usb-group".into(),
            blocks: vec![KernelBlockIdentity {
                block_path: "sdb".into(),
                device_number: 2048,
                disk_sequence: 10,
                canonical_sysfs: PathBuf::from("/sys/devices/pci/block/sdb"),
                physical_parent: PathBuf::from("/sys/devices/pci/block/sdb"),
                mounted_as_root: false,
                swap_in_use: false,
                has_holders: false,
            }],
        };
        let mut after = first.clone();
        after.blocks[0].disk_sequence = 11;
        assert!(review_stable_kernel_group(&first, &after).is_err());
        assert!(review_stable_kernel_group(&first, &first).is_ok());
    }
}
