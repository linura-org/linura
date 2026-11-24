//! Strict, read-only kernel backlight discovery.
//!
//! A kernel sysfs inventory is **not** a logind authorization, an approved
//! backlight minimum, a generation-bound Control observation, or evidence that
//! hardware brightness was successfully changed. This adapter never writes
//! kernel attributes or creates an executable operation.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, fstatfs, open};

const BACKLIGHT_CLASS: &str = "/sys/class/backlight";
const DEVICES_ROOT: &str = "/sys/devices";
const SYSFS_MAGIC: i64 = 0x6265_6572;
const MAX_DEVICES: usize = 16;
const MAX_FACT_BYTES: u64 = 32;
const MAX_DEVICE_NAME: usize = 64;
const MAX_NATIVE_PATH_BYTES: usize = 512;

/// A read-only kernel object correlation. These fields do not prove that a
/// replacement device could not reuse an inode or that a session owns it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelBacklightIdentity {
    pub name: String,
    pub device_path: PathBuf,
    pub inode: u64,
    pub mount_device: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelBacklightKind {
    Raw,
    Platform,
    Firmware,
}

/// Native current and measured brightness remain distinct. A successful write
/// would still require independently reobserving the actual native state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelBacklightSnapshot {
    pub identity: KernelBacklightIdentity,
    pub kind: KernelBacklightKind,
    pub maximum: u32,
    pub requested_brightness: u32,
    pub actual_brightness: u32,
    pub power: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelBacklightError {
    Unavailable,
    UntrustedSysfs,
    InvalidDevice,
    InvalidValue,
    TooManyDevices,
    DeviceChanged,
}

/// Observe bounded physical-looking Linux backlights. An empty result means
/// there is no verified hardware backlight here. No virtual/gamma substitute.
///
/// The caller must *not* convert these records directly to mutation permits.
/// A future session observer must additionally authenticate the exact boot,
/// active session, seat, UID, logind unique owner, source generation and a
/// hardware-qualified nonzero visible minimum.
pub fn observe_kernel_backlights() -> Result<Vec<KernelBacklightSnapshot>, KernelBacklightError> {
    let directory = File::open(BACKLIGHT_CLASS).map_err(|_| KernelBacklightError::Unavailable)?;
    verify_sysfs_directory(&directory)?;
    let entries = fs::read_dir(BACKLIGHT_CLASS).map_err(|_| KernelBacklightError::Unavailable)?;
    let mut observed = Vec::new();
    let mut seen_names = BTreeSet::new();
    let mut seen_devices = BTreeSet::new();
    let mut count = 0_usize;

    for entry in entries {
        let entry = entry.map_err(|_| KernelBacklightError::Unavailable)?;
        count = count
            .checked_add(1)
            .ok_or(KernelBacklightError::TooManyDevices)?;
        if count > MAX_DEVICES {
            return Err(KernelBacklightError::TooManyDevices);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| KernelBacklightError::InvalidDevice)?;
        if !valid_device_name(&name) || !seen_names.insert(name.clone()) {
            return Err(KernelBacklightError::InvalidDevice);
        }
        let alias = Path::new(BACKLIGHT_CLASS).join(&name);
        let resolved = alias
            .canonicalize()
            .map_err(|_| KernelBacklightError::DeviceChanged)?;
        if !physical_device_path(&resolved)
            || resolved.file_name().and_then(|leaf| leaf.to_str()) != Some(name.as_str())
            || resolved
                .parent()
                .and_then(Path::file_name)
                .is_none_or(|parent| parent != "backlight")
        {
            // Virtual backlights are not evidence of a physical hardware
            // brightness controller and must never be used as a fallback.
            continue;
        }
        if !seen_devices.insert(resolved.clone()) {
            return Err(KernelBacklightError::InvalidDevice);
        }
        observed.push(observe_device(&name, &alias, &resolved)?);
    }

    observed.sort_by(|left, right| left.identity.name.cmp(&right.identity.name));
    Ok(observed)
}

fn observe_device(
    name: &str,
    alias: &Path,
    resolved: &Path,
) -> Result<KernelBacklightSnapshot, KernelBacklightError> {
    let directory = File::open(resolved).map_err(|_| KernelBacklightError::DeviceChanged)?;
    verify_sysfs_directory(&directory)?;
    let before = directory
        .metadata()
        .map_err(|_| KernelBacklightError::DeviceChanged)?;
    let kind = parse_kind(&read_sysfs_fact(&resolved.join("type"))?)?;
    let maximum = parse_native_value(&read_sysfs_fact(&resolved.join("max_brightness"))?)?;
    let requested_brightness = parse_native_value(&read_sysfs_fact(&resolved.join("brightness"))?)?;
    let actual_brightness =
        parse_native_value(&read_sysfs_fact(&resolved.join("actual_brightness"))?)?;
    let power = parse_native_value(&read_sysfs_fact(&resolved.join("bl_power"))?)?;

    if maximum == 0 || requested_brightness > maximum || actual_brightness > maximum || power > 4 {
        return Err(KernelBacklightError::InvalidValue);
    }

    // A replacement, hotplug, or concurrent brightness writer must not yield
    // a fabricated coherent sample. Recheck the canonical alias and native
    // facts; any changed identity or value makes this sample unusable.
    if alias
        .canonicalize()
        .map_err(|_| KernelBacklightError::DeviceChanged)?
        != resolved
    {
        return Err(KernelBacklightError::DeviceChanged);
    }
    let after = fs::metadata(resolved).map_err(|_| KernelBacklightError::DeviceChanged)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(KernelBacklightError::DeviceChanged);
    }
    if read_sysfs_fact(&resolved.join("type"))? != kind_bytes(kind)
        || parse_native_value(&read_sysfs_fact(&resolved.join("max_brightness"))?)? != maximum
        || parse_native_value(&read_sysfs_fact(&resolved.join("brightness"))?)?
            != requested_brightness
        || parse_native_value(&read_sysfs_fact(&resolved.join("actual_brightness"))?)?
            != actual_brightness
        || parse_native_value(&read_sysfs_fact(&resolved.join("bl_power"))?)? != power
    {
        return Err(KernelBacklightError::DeviceChanged);
    }

    Ok(KernelBacklightSnapshot {
        identity: KernelBacklightIdentity {
            name: name.to_owned(),
            device_path: resolved.to_path_buf(),
            inode: before.ino(),
            mount_device: before.dev(),
        },
        kind,
        maximum,
        requested_brightness,
        actual_brightness,
        power,
    })
}

fn verify_sysfs_directory(directory: &File) -> Result<(), KernelBacklightError> {
    let metadata = directory
        .metadata()
        .map_err(|_| KernelBacklightError::UntrustedSysfs)?;
    let fs = fstatfs(directory).map_err(|_| KernelBacklightError::UntrustedSysfs)?;
    if fs.f_type != SYSFS_MAGIC
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(KernelBacklightError::UntrustedSysfs);
    }
    Ok(())
}

fn read_sysfs_fact(path: &Path) -> Result<Vec<u8>, KernelBacklightError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| KernelBacklightError::Unavailable)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| KernelBacklightError::UntrustedSysfs)?;
    let fs = fstatfs(&file).map_err(|_| KernelBacklightError::UntrustedSysfs)?;
    if fs.f_type != SYSFS_MAGIC
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(KernelBacklightError::UntrustedSysfs);
    }
    let mut bytes = Vec::new();
    file.take(MAX_FACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KernelBacklightError::Unavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_FACT_BYTES {
        return Err(KernelBacklightError::InvalidValue);
    }
    Ok(bytes)
}

fn parse_native_value(bytes: &[u8]) -> Result<u32, KernelBacklightError> {
    let text = std::str::from_utf8(bytes).map_err(|_| KernelBacklightError::InvalidValue)?;
    let trimmed = text
        .strip_suffix('\n')
        .ok_or(KernelBacklightError::InvalidValue)?;
    if trimmed.is_empty()
        || trimmed.len() > 10
        || (trimmed.len() > 1 && trimmed.starts_with('0'))
        || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(KernelBacklightError::InvalidValue);
    }
    trimmed
        .parse::<u32>()
        .map_err(|_| KernelBacklightError::InvalidValue)
}

fn parse_kind(bytes: &[u8]) -> Result<KernelBacklightKind, KernelBacklightError> {
    match bytes {
        b"raw\n" => Ok(KernelBacklightKind::Raw),
        b"platform\n" => Ok(KernelBacklightKind::Platform),
        b"firmware\n" => Ok(KernelBacklightKind::Firmware),
        _ => Err(KernelBacklightError::InvalidValue),
    }
}

fn kind_bytes(kind: KernelBacklightKind) -> Vec<u8> {
    match kind {
        KernelBacklightKind::Raw => b"raw\n".to_vec(),
        KernelBacklightKind::Platform => b"platform\n".to_vec(),
        KernelBacklightKind::Firmware => b"firmware\n".to_vec(),
    }
}

fn valid_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DEVICE_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name != "."
        && name != ".."
}

fn physical_device_path(path: &Path) -> bool {
    path.as_os_str().len() <= MAX_NATIVE_PATH_BYTES
        && path.starts_with(DEVICES_ROOT)
        && path != Path::new(DEVICES_ROOT)
        && !path
            .components()
            .any(|c| c == Component::Normal("virtual".as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_values_are_canonical_bounded_u32() {
        assert_eq!(parse_native_value(b"0\n"), Ok(0));
        assert_eq!(parse_native_value(b"4294967295\n"), Ok(u32::MAX));
        for input in [
            b"".as_slice(),
            b"01\n",
            b"+1\n",
            b" 1\n",
            b"1 \n",
            b"1",
            b"4294967296\n",
            b"-1\n",
            b"1\n2\n",
        ] {
            assert_eq!(
                parse_native_value(input),
                Err(KernelBacklightError::InvalidValue)
            );
        }
    }

    #[test]
    fn unsupported_device_types_and_unknown_power_are_never_guessed() {
        assert_eq!(parse_kind(b"raw\n"), Ok(KernelBacklightKind::Raw));
        assert_eq!(parse_kind(b"platform\n"), Ok(KernelBacklightKind::Platform));
        assert_eq!(parse_kind(b"firmware\n"), Ok(KernelBacklightKind::Firmware));
        for value in [b"virtual\n".as_slice(), b"Raw\n", b"raw", b"unknown\n"] {
            assert_eq!(parse_kind(value), Err(KernelBacklightError::InvalidValue));
        }
    }

    #[test]
    fn source_names_and_native_paths_must_not_escape_physical_sysfs() {
        for invalid in [
            "",
            ".",
            "..",
            "../intel_backlight",
            "evil/name",
            "x\n",
            "a b",
        ] {
            assert!(!valid_device_name(invalid));
        }
        assert!(valid_device_name("intel_backlight"));
        assert!(valid_device_name("amdgpu_bl0"));
        assert!(physical_device_path(Path::new(
            "/sys/devices/pci0000:00/0000:00:02.0/backlight"
        )));
        assert!(!physical_device_path(Path::new("/tmp/fake_backlight")));
        assert!(!physical_device_path(Path::new(
            "/sys/devices/virtual/backlight/mock"
        )));
        assert!(!physical_device_path(Path::new("/sys/devices")));
    }
}
