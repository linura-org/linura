//! Read-only Arch ALPM *installed* database observations.
//! Local installed metadata is not a verified signed repository catalog,
//! not a transaction preflight, and never a grant to execute pacman.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use rustix::fs::{open, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::{capability, next_sequence, now_unix_ms, provider_id};

const PROVIDER: &str = "alpm-installed";
const CAPABILITY: &str = "alpm.package.installed.observe";
const PREFIX: &str = "alpm:installed:";
const MAX_PACKAGES: usize = 8192;
const MAX_DESC: usize = 128 * 1024;
const MAX_TOTAL: usize = 48 * 1024 * 1024;
const MAX_DIR_ENTRIES: usize = MAX_PACKAGES + 1;
const FRESH_MS: u64 = 1000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstalledPackage {
    name: String,
    version: String,
    architecture: String,
    reason: u64,
    installed_size: u64,
    installed_size_known: bool,
    depends_count: u64,
    provides_count: u64,
    conflicts_count: u64,
    replaces_count: u64,
    directory: String,
    desc_sha256: String,
}

#[derive(Debug)]
pub struct AlpmInstalledObserver {
    local_db: PathBuf,
    lock_path: PathBuf,
    require_root_owner: bool,
    sequence: AtomicU64,
}

impl AlpmInstalledObserver {
    #[must_use]
    pub fn system() -> Self {
        Self {
            local_db: PathBuf::from("/var/lib/pacman/local"),
            lock_path: PathBuf::from("/var/lib/pacman/db.lck"),
            require_root_owner: true,
            sequence: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn fixture(local_db: PathBuf, lock_path: PathBuf) -> Self {
        Self {
            local_db,
            lock_path,
            require_root_owner: false,
            sequence: AtomicU64::new(0),
        }
    }

    fn inventory(&self) -> Result<BTreeMap<String, InstalledPackage>, ProviderError> {
        self.ensure_unlocked()?;
        let before = fs::symlink_metadata(&self.local_db).map_err(source_error)?;
        self.check_dir(&before)?;
        let mut entries = fs::read_dir(&self.local_db)
            .map_err(source_error)?
            .take(MAX_DIR_ENTRIES)
            .collect::<Result<Vec<_>, _>>()
            .map_err(source_error)?;
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(invalid("Installed package directory exceeds bounded inventory"));
        }
        entries.sort_by_key(|entry| entry.file_name());
        let mut packages = BTreeMap::new();
        let mut total = 0_usize;
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| invalid("Non-UTF8 installed package directory"))?;
            if name.is_empty() || name == "." || name == ".." || name.len() > 220
                || name.contains('/') || name.chars().any(char::is_control)
            {
                return Err(invalid("Invalid installed package directory"));
            }
            let kind = entry.file_type().map_err(source_error)?;
            if kind.is_symlink() || !kind.is_dir() {
                return Err(invalid("Unsafe local ALPM package directory"));
            }
            let dir = entry.path();
            let dir_before = fs::symlink_metadata(&dir).map_err(source_error)?;
            self.check_dir(&dir_before)?;
            let desc = dir.join("desc");
            let bytes = self.read_desc(&desc)?;
            total = total.checked_add(bytes.len()).ok_or_else(|| invalid("ALPM byte-budget overflow"))?;
            if total > MAX_TOTAL {
                return Err(invalid("ALPM local database exceeds byte budget"));
            }
            let parsed = parse_desc(&bytes, name)?;
            if packages.insert(parsed.name.clone(), parsed).is_some() {
                return Err(invalid("Duplicate installed package name"));
            }
            let dir_after = fs::symlink_metadata(&dir).map_err(source_error)?;
            if !same_revision(&dir_before, &dir_after) {
                return Err(invalid("ALPM package directory changed during observation"));
            }
        }
        let after = fs::symlink_metadata(&self.local_db).map_err(source_error)?;
        if !same_revision(&before, &after) {
            return Err(invalid("ALPM local database changed during observation"));
        }
        self.ensure_unlocked()?;
        Ok(packages)
    }

    fn check_dir(&self, meta: &Metadata) -> Result<(), ProviderError> {
        if !meta.is_dir() || meta.file_type().is_symlink()
            || (self.require_root_owner && meta.uid() != 0)
        {
            return Err(invalid("ALPM database directory identity or ownership is unsafe"));
        }
        Ok(())
    }

    fn ensure_unlocked(&self) -> Result<(), ProviderError> {
        match fs::symlink_metadata(&self.lock_path) {
            Ok(_) => Err(ProviderError::Unavailable(
                "ALPM database lock exists; package observation is not transaction-stable".into(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(source_error(error)),
        }
    }

    fn read_desc(&self, path: &Path) -> Result<Vec<u8>, ProviderError> {
        let fd = open(path, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())
            .map_err(|_| invalid("Unsafe ALPM descriptor open"))?;
        let mut file = File::from(fd);
        let before = file.metadata().map_err(source_error)?;
        if !before.is_file() || before.len() > MAX_DESC as u64
            || (self.require_root_owner && before.uid() != 0)
            || before.nlink() != 1
        {
            return Err(invalid("Unsafe ALPM descriptor ownership, links or size"));
        }
        let mut bytes = Vec::new();
        file.by_ref().take((MAX_DESC + 1) as u64).read_to_end(&mut bytes)
            .map_err(source_error)?;
        let after = file.metadata().map_err(source_error)?;
        let path_now = fs::symlink_metadata(path).map_err(source_error)?;
        if bytes.len() > MAX_DESC || bytes.len() as u64 != before.len()
            || !same_revision(&before, &after) || !same_revision(&after, &path_now)
            || !path_now.is_file() || path_now.file_type().is_symlink()
        {
            return Err(invalid("ALPM descriptor changed or substituted during observation"));
        }
        Ok(bytes)
    }

    fn resource_for(name: &str) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!("{PREFIX}{name}"))
            .map_err(|_| invalid("ALPM package resource exceeds typed identifier bound"))
    }
}

impl Observer for AlpmInstalledObserver {
    fn observer_id(&self) -> ProviderId { provider_id(PROVIDER) }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let h = self.health();
        vec![capability(CAPABILITY, PROVIDER, h.availability, h.reason)]
    }

    fn health(&self) -> ProviderHealth {
        let ready = self.ensure_unlocked().is_ok()
            && fs::symlink_metadata(&self.local_db)
                .is_ok_and(|m| self.check_dir(&m).is_ok());
        ProviderHealth {
            provider: provider_id(PROVIDER),
            availability: if ready { ProviderAvailability::Available } else { ProviderAvailability::Unavailable },
            reason: if ready { None } else {
                Some("Local ALPM database unavailable, locked or unsafe".into())
            },
        }
    }

    fn requires_live_health_preflight(&self) -> bool {
        false // Exact read repeats lock and source identity checks independently.
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.inventory()?.keys().map(|name| Self::resource_for(name)).collect()
    }

    fn observe_authoritative(
        &self, resource: &ResourceId, capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if capability.as_str() != CAPABILITY {
            return Err(ProviderError::Unsupported("Not an installed ALPM package capability".into()));
        }
        let name = resource.as_str().strip_prefix(PREFIX)
            .ok_or_else(|| ProviderError::Unsupported("Not an exact ALPM installed-package resource".into()))?;
        if !canonical_package_name(name) || Self::resource_for(name)?.as_str() != resource.as_str() {
            return Err(invalid("Invalid ALPM installed-package resource"));
        }
        let observed = self.inventory()?.remove(name)
            .ok_or_else(|| ProviderError::Unavailable("Installed package is absent".into()))?;
        Ok(ObservationEnvelope {
            provider: provider_id(PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::Filesystem,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: FRESH_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("name".into(), ObservedValue::Text(observed.name)),
                ("version".into(), ObservedValue::Text(observed.version)),
                ("architecture".into(), ObservedValue::Text(observed.architecture)),
                ("reason".into(), ObservedValue::U64(observed.reason)),
                ("installed_size".into(), ObservedValue::U64(observed.installed_size)),
                ("installed_size_known".into(), ObservedValue::Bool(observed.installed_size_known)),
                ("depends_count".into(), ObservedValue::U64(observed.depends_count)),
                ("provides_count".into(), ObservedValue::U64(observed.provides_count)),
                ("conflicts_count".into(), ObservedValue::U64(observed.conflicts_count)),
                ("replaces_count".into(), ObservedValue::U64(observed.replaces_count)),
                ("source_directory".into(), ObservedValue::Text(observed.directory)),
                ("desc_sha256".into(), ObservedValue::Text(observed.desc_sha256)),
                ("signed_repository_verified".into(), ObservedValue::Bool(false)),
                ("complete_transaction_preflight".into(), ObservedValue::Bool(false)),
                ("effect_authorized".into(), ObservedValue::Bool(false)),
            ]),
        })
    }
}

fn invalid(message: &'static str) -> ProviderError { ProviderError::InvalidState(message.into()) }
fn source_error(_: std::io::Error) -> ProviderError {
    ProviderError::Unavailable("Cannot securely read installed ALPM metadata".into())
}

fn same_revision(left: &Metadata, right: &Metadata) -> bool {
    (left.dev(),left.ino(),left.len(),left.uid(),left.mode(),left.mtime(),left.mtime_nsec(),left.ctime(),left.ctime_nsec())
        == (right.dev(),right.ino(),right.len(),right.uid(),right.mode(),right.mtime(),right.mtime_nsec(),right.ctime(),right.ctime_nsec())
}

fn canonical_package_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 190 && !name.starts_with('-')
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b".:+_~@-".contains(&b))
}

fn parse_desc(content: &[u8], directory: &str) -> Result<InstalledPackage, ProviderError> {
    let text = std::str::from_utf8(content).map_err(|_| invalid("ALPM descriptor is not UTF-8"))?;
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut active: Option<&str> = None;
    let mut sections = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            let section = &line[1..line.len()-1];
            if !section.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                || !sections.insert(section.to_owned()) {
                return Err(invalid("Duplicate or invalid ALPM descriptor field"));
            }
            fields.insert(section.to_owned(), Vec::new());
            active = Some(section);
            continue;
        }
        if line.is_empty() { continue; }
        let key = active.ok_or_else(|| invalid("ALPM descriptor has unscoped value"))?;
        if line.chars().any(char::is_control) || line.len() > 4096 {
            return Err(invalid("Unsafe ALPM descriptor value"));
        }
        fields.get_mut(key).ok_or_else(|| invalid("Unknown ALPM descriptor section"))?.push(line.into());
    }
    let one = |key: &str| -> Result<String, ProviderError> {
        let items = fields.get(key).ok_or_else(|| invalid("Required ALPM field missing"))?;
        if items.len() != 1 { return Err(invalid("ALPM scalar field is ambiguous")); }
        Ok(items[0].clone())
    };
    let name=one("NAME")?;
    let version=one("VERSION")?;
    let architecture=one("ARCH")?;
    // ALPM local DB uses %SIZE%; %ISIZE% belongs to the sync/repo DB.
    // Local %REASON% and %SIZE% are optional in the native specification.
    let reason=fields.get("REASON").map_or_else(|| Ok("0".to_owned()), |_| one("REASON"))?;
    let installed_size_known=fields.contains_key("SIZE");
    let installed_size=if installed_size_known { one("SIZE")? } else { "0".into() };
    if !canonical_package_name(&name) || !valid_version(&version)
        || !(architecture == "any" || (architecture.len() <= 32
          && architecture.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))))
        || directory != format!("{name}-{version}") {
        return Err(invalid("ALPM directory/package identity mismatch"));
    }
    let reason = reason.parse::<u64>().map_err(|_| invalid("Invalid ALPM install reason"))?;
    if reason > 1 { return Err(invalid("ALPM install reason outside native enum")); }
    let installed_size = installed_size.parse::<u64>()
        .map_err(|_| invalid("Invalid ALPM installed size"))?;
    let count = |key: &str| -> Result<u64, ProviderError> {
        let values=fields.get(key).map_or(0, Vec::len);
        u64::try_from(values).map_err(|_| invalid("ALPM descriptor list exceeds bound"))
    };
    let hash=Sha256::digest(content);
    Ok(InstalledPackage {
        name, version, architecture, reason, installed_size, installed_size_known,
        depends_count: count("DEPENDS")?, provides_count: count("PROVIDES")?,
        conflicts_count: count("CONFLICTS")?, replaces_count: count("REPLACES")?,
        directory: directory.into(), desc_sha256: format!("{hash:x}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn fixture() -> (PathBuf,PathBuf,PathBuf) {
        let n=NEXT.fetch_add(1,Ordering::Relaxed);
        let root=std::env::temp_dir().join(format!("linura-s23-alpm-{}-{n}",std::process::id()));
        let local=root.join("local");
        let lock=root.join("db.lck");
        assert!(fs::create_dir_all(&local).is_ok());
        (root,local,lock)
    }
    fn package(local:&Path, name:&str,version:&str, data:&[u8]) {
        let dir=local.join(format!("{name}-{version}"));
        assert!(fs::create_dir_all(&dir).is_ok());
        assert!(fs::write(dir.join("desc"),data).is_ok());
    }
    const VALID: &[u8] = b"%NAME%\nexample\n\n%VERSION%\n1.2-1\n\n%ARCH%\nx86_64\n\n%REASON%\n0\n\n%SIZE%\n42\n\n%DEPENDS%\nglibc\n\n";
    #[test]
    fn exact_local_inventory_carries_revision_not_signing_authority() {
        let (root,local,lock)=fixture();
        package(&local,"example","1.2-1",VALID);
        let observer=AlpmInstalledObserver::fixture(local,lock);
        let cap=CapabilityId::new(CAPABILITY).unwrap_or_else(|e| unreachable!("{e}"));
        let res=AlpmInstalledObserver::resource_for("example").unwrap_or_else(|e| unreachable!("{e}"));
        let row=observer.observe_authoritative(&res,&cap).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(row.attributes["version"],ObservedValue::Text("1.2-1".into()));
        assert_eq!(row.attributes["depends_count"],ObservedValue::U64(1));
        assert_eq!(row.attributes["installed_size"],ObservedValue::U64(42));
        assert_eq!(row.attributes["installed_size_known"],ObservedValue::Bool(true));
        assert_eq!(row.attributes["signed_repository_verified"],ObservedValue::Bool(false));
        assert_eq!(row.attributes["effect_authorized"],ObservedValue::Bool(false));
        assert_eq!(observer.resources().unwrap_or_else(|e| unreachable!("{e}")).len(),1);
        let _=fs::remove_dir_all(root);
    }
    #[test]
    fn lock_and_invalid_source_fail_closed() {
        let (root,local,lock)=fixture();
        package(&local,"example","1.2-1",VALID);
        let observer=AlpmInstalledObserver::fixture(local.clone(),lock.clone());
        assert!(fs::write(&lock,b"owned").is_ok());
        assert!(matches!(observer.resources(),Err(ProviderError::Unavailable(_))));
        assert!(fs::remove_file(&lock).is_ok());
        package(&local,"evil","1.2-1",VALID); // directory name disagrees with descriptor
        assert!(matches!(observer.resources(),Err(ProviderError::InvalidState(_))));
        let _=fs::remove_dir_all(root);
    }
    #[test]
    fn malformed_duplicate_sections_are_not_accepted() {
        let doubled=b"%NAME%\nexample\n\n%NAME%\nwrong\n\n%VERSION%\n1.2-1\n";
        assert!(parse_desc(doubled,"example-1.2-1").is_err());
        assert!(parse_desc(b"%NAME%\nexample\n","example-1.2-1").is_err());
        assert!(!canonical_package_name("../tmp"));
        assert!(!canonical_package_name("-invalid"));
    }
}
