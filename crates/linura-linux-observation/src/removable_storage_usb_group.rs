//! Read-only, kernel-backed USB device and sibling completeness review.
//!
//! UDisks2 SiblingId is an untrusted correlation, not a physical power-domain
//! oracle. An independently enumerated sysfs set must not contain any
//! block/partition device omitted from the selected UDisks2 sibling group.
//! This does NOT prove the entire upstream hub power domain or live writers.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use linura_provider_sdk::ProviderError;

use crate::removable_storage_kernel_device::{KernelBlockIdentity, sysfs_device};

const MAX_KERNEL_BLOCK_LINKS: usize = 1024;
const MAX_SYSFS_PARENTS: usize = 32;
const SYSFS_BLOCK_PATH: &str = "/sys/dev/block";

fn invalid(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.into())
}

/// Identify the *nearest USB device*, not the logical SCSI path, by the
/// kernel's device attributes. No caller path is accepted by this API.
/// A USB interface directory contains a colon and is not itself a physical
/// USB-device root; interface children are grouped beneath the device.
fn usb_device_parent(path: &Path) -> Result<PathBuf, ProviderError> {
    if !path.starts_with("/sys/devices/") {
        return Err(invalid("block does not have physical sysfs ancestry"));
    }
    for parent in path.ancestors().take(MAX_SYSFS_PARENTS) {
        if parent == Path::new("/sys/devices") {
            break;
        }
        if parent.join("idVendor").is_file()
            && parent.join("idProduct").is_file()
            && parent.join("busnum").is_file()
            && parent.join("devnum").is_file()
        {
            return Ok(parent.to_path_buf());
        }
    }
    Err(invalid("USB physical device ancestry is not provable"))
}

/// Check a whole physical USB group, after the native observer has already
/// proved the selected drive, complete UDisks2 partition ancestry and seat.
/// Refuse any unreported kernel block device sharing the USB device. The
/// kernel enumeration is bounded and failed/changed sysfs links are denied.
pub fn review_whole_usb_device(selected: &[KernelBlockIdentity]) -> Result<(), ProviderError> {
    if selected.is_empty() {
        return Err(invalid("USB sibling group is empty"));
    }
    let mut usb = None;
    let mut reported = BTreeSet::new();
    for block in selected {
        let parent = usb_device_parent(&block.canonical_sysfs)?;
        if let Some(existing) = &usb {
            if existing != &parent {
                return Err(invalid(
                    "provider sibling group crosses physical USB devices",
                ));
            }
        } else {
            usb = Some(parent);
        }
        if !reported.insert(block.device_number) {
            return Err(invalid("provider repeated a kernel USB member"));
        }
        if sysfs_device(&block.canonical_sysfs)? != block.device_number {
            return Err(invalid("provider block and kernel identity differ"));
        }
    }
    let usb = usb.ok_or_else(|| invalid("missing physical USB device"))?;
    let mut actual = BTreeSet::new();
    for (count, item) in fs::read_dir(SYSFS_BLOCK_PATH)
        .map_err(|_| invalid("kernel USB block enumeration is unavailable"))?
        .enumerate()
    {
        if count >= MAX_KERNEL_BLOCK_LINKS {
            return Err(invalid("kernel USB block inventory exceeds bound"));
        }
        let link = item
            .map_err(|_| invalid("kernel USB block enumeration changed"))?
            .path();
        let target =
            fs::canonicalize(link).map_err(|_| invalid("kernel USB block link changed"))?;
        if !target.starts_with("/sys/devices/") {
            return Err(invalid(
                "kernel sysfs block path escaped physical device root",
            ));
        }
        // Unrelated kernel virtual devices are not part of a physical USB
        // device. Physical SCSI or PCI blocks without a USB ancestor are not
        // in this group's power or media-ejection scope.
        if target.starts_with("/sys/devices/virtual/") {
            continue;
        }
        match usb_device_parent(&target) {
            Ok(parent) if parent == usb => {
                let device_number = sysfs_device(&target)?;
                if !actual.insert(device_number) {
                    return Err(invalid("duplicate physical kernel USB block"));
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
    review_complete_usb_inventory(&reported, &actual)
}

fn review_complete_usb_inventory(
    reported: &BTreeSet<u64>,
    kernel: &BTreeSet<u64>,
) -> Result<(), ProviderError> {
    if reported.is_empty() || reported != kernel {
        return Err(invalid(
            "UDisks2 sibling group omitted or misidentified a physical USB block",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_completeness_rejects_hidden_lun_partition_and_false_extra() {
        let reported = BTreeSet::from([2048, 2049, 2064]);
        assert!(review_complete_usb_inventory(&reported, &reported).is_ok());
        assert!(
            review_complete_usb_inventory(&reported, &BTreeSet::from([2048, 2049, 2064, 2065]))
                .is_err()
        );
        assert!(review_complete_usb_inventory(&reported, &BTreeSet::from([2048, 2049])).is_err());
        assert!(review_complete_usb_inventory(&BTreeSet::new(), &BTreeSet::new()).is_err());
    }

    #[test]
    fn usb_device_ancestry_is_physical_and_not_an_interface_or_disk_name() {
        let base = Path::new("/sys/devices/pci0000:00/0000:00:14.0/usb1");
        assert!(usb_device_parent(Path::new("/sys/devices/virtual/block/loop0")).is_err());
        assert!(usb_device_parent(Path::new("/tmp/usb1/sdb")).is_err());
        // A fixture path without native idVendor and busnum cannot be
        // presented as a real USB ancestor.
        assert!(usb_device_parent(&base.join("1-2/1-2:1.0/host0/block/sdb")).is_err());
    }
}
