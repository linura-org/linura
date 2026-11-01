//! Bounded, read-only XDG application source observation.
//! This is source evidence, never a launch grant or an application executor.
//! The existing Quickshell launcher remains independently responsible for launch.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest, Sha256};

use super::{capability, next_sequence, now_unix_ms, provider_id};

const PROVIDER: &str = "xdg-applications";
const CAPABILITY: &str = "desktop.application.observe";
const RESOURCE_PREFIX: &str = "xdg:application:";
const MAX_ROOTS: usize = 16;
const MAX_FILES: usize = 4_096;
const MAX_DEPTH: usize = 8;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const FRESHNESS_MS: u64 = 1_000;

#[derive(Clone, Debug)]
struct DesktopSource {
    id: String,
    name: String,
    path: PathBuf,
    digest: String,
    uid: u32,
    root_priority: u64,
    hidden: bool,
    no_display: bool,
    terminal: bool,
    try_exec_present: bool,
    desktop_restricted: bool,
}

#[derive(Debug)]
pub struct XdgApplicationObserver {
    roots: Vec<PathBuf>,
    desktop: Option<String>,
    environment_error: Option<String>,
    sequence: AtomicU64,
}

impl XdgApplicationObserver {
    /// Resolve the calling *process* user-session data roots. It is not a
    /// per-client identity oracle; Control owns authenticated caller scoping.
    #[must_use]
    pub fn from_environment() -> Self {
        match current_roots() {
            Ok(roots) => Self {
                roots,
                desktop: env::var("XDG_CURRENT_DESKTOP").ok(),
                environment_error: None,
                sequence: AtomicU64::new(0),
            },
            Err(problem) => Self {
                roots: Vec::new(),
                desktop: None,
                environment_error: Some(problem),
                sequence: AtomicU64::new(0),
            },
        }
    }

    #[cfg(test)]
    fn for_test(roots: Vec<PathBuf>, desktop: Option<&str>) -> Self {
        Self {
            roots,
            desktop: desktop.map(str::to_owned),
            environment_error: None,
            sequence: AtomicU64::new(0),
        }
    }

    fn inventory(&self) -> Result<BTreeMap<String, DesktopSource>, ProviderError> {
        if let Some(problem) = &self.environment_error {
            return Err(ProviderError::Unavailable(problem.clone()));
        }
        let mut seen = BTreeSet::new();
        let mut sources = BTreeMap::new();
        let mut file_count = 0;
        let mut total_bytes = 0;
        for (index, root) in self.roots.iter().enumerate() {
            let directory = root.join("applications");
            match fs::symlink_metadata(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(source_error(error)),
                Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                    return Err(ProviderError::InvalidState("Unsafe XDG applications root".into()));
                }
                Ok(_) => {}
            }
            scan_directory(
                &directory,
                &directory,
                index as u64,
                self.desktop.as_deref(),
                &mut seen,
                &mut sources,
                &mut file_count,
                &mut total_bytes,
            )?;
        }
        Ok(sources)
    }

    fn exact_resource(id: &str) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!("{RESOURCE_PREFIX}{id}")).map_err(|_| {
            ProviderError::InvalidState("XDG desktop ID exceeds the typed resource bound".into())
        })
    }
}

impl Observer for XdgApplicationObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(PROVIDER)
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![capability(
            CAPABILITY,
            PROVIDER,
            health.availability,
            health.reason,
        )]
    }

    fn health(&self) -> ProviderHealth {
        let available = self.environment_error.is_none()
            && self.roots.iter().any(|root| root.join("applications").is_dir());
        ProviderHealth {
            provider: provider_id(PROVIDER),
            availability: if available {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::Unavailable
            },
            reason: if available {
                None
            } else {
                Some(self.environment_error.clone().unwrap_or_else(|| {
                    "No current XDG applications directory is available".into()
                }))
            },
        }
    }

    fn requires_live_health_preflight(&self) -> bool {
        false // Every read independently rescans its bounded native source.
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.inventory()?
            .keys()
            .map(|id| Self::exact_resource(id))
            .collect()
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if capability.as_str() != CAPABILITY {
            return Err(ProviderError::Unsupported("Not an XDG application observation".into()));
        }
        let id = resource.as_str().strip_prefix(RESOURCE_PREFIX).ok_or_else(|| {
            ProviderError::Unsupported("Not an exact XDG application resource".into())
        })?;
        if id.is_empty() || Self::exact_resource(id)?.as_str() != resource.as_str() {
            return Err(ProviderError::InvalidState("Invalid XDG application resource".into()));
        }
        let source = self.inventory()?.remove(id).ok_or_else(|| {
            ProviderError::Unavailable("Desktop application is no longer present".into())
        })?;
        let source_path = source.path.to_str().ok_or_else(|| {
            ProviderError::InvalidState("Non-UTF8 application source path".into())
        })?;
        if source_path.chars().any(char::is_control) {
            return Err(ProviderError::InvalidState("Unsafe application source path".into()));
        }
        Ok(ObservationEnvelope {
            provider: provider_id(PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::Filesystem,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: FRESHNESS_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("desktop_id".into(), ObservedValue::Text(source.id)),
                ("name".into(), ObservedValue::Text(source.name)),
                ("source_path".into(), ObservedValue::Text(source_path.into())),
                ("source_sha256".into(), ObservedValue::Text(source.digest)),
                ("source_uid".into(), ObservedValue::U64(u64::from(source.uid))),
                ("source_priority".into(), ObservedValue::U64(source.root_priority)),
                ("hidden".into(), ObservedValue::Bool(source.hidden)),
                ("no_display".into(), ObservedValue::Bool(source.no_display)),
                ("terminal".into(), ObservedValue::Bool(source.terminal)),
                ("try_exec_present".into(), ObservedValue::Bool(source.try_exec_present)),
                ("desktop_restricted".into(), ObservedValue::Bool(source.desktop_restricted)),
                // Never expose raw Exec/argv. This observation cannot authorize launch.
                ("launch_authorized".into(), ObservedValue::Bool(false)),
            ]),
        })
    }
}

fn current_roots() -> Result<Vec<PathBuf>, String> {
    let home = env::var_os("HOME").ok_or("HOME is unavailable")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("HOME is not absolute".into());
    }
    let data_home = match env::var_os("XDG_DATA_HOME") {
        Some(value) if !value.is_empty() => absolute_path(value)?,
        _ => home.join(".local/share"),
    };
    let data_dirs = match env::var_os("XDG_DATA_DIRS") {
        Some(value) if !value.is_empty() => value,
        _ => OsString::from("/usr/local/share:/usr/share"),
    };
    let dirs = data_dirs.to_str().ok_or("XDG_DATA_DIRS is not UTF-8")?;
    let mut roots = vec![data_home];
    for raw in dirs.split(':') {
        if raw.is_empty() {
            return Err("XDG_DATA_DIRS has an empty directory entry".into());
        }
        roots.push(absolute_path(OsString::from(raw))?);
    }
    if roots.len() > MAX_ROOTS {
        return Err("XDG_DATA_DIRS exceeds the bounded root count".into());
    }
    Ok(roots)
}

fn absolute_path(value: OsString) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("XDG application root is not absolute".into());
    }
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn scan_directory(
    current: &Path,
    root: &Path,
    priority: u64,
    desktop: Option<&str>,
    seen: &mut BTreeSet<String>,
    sources: &mut BTreeMap<String, DesktopSource>,
    files: &mut usize,
    total: &mut usize,
) -> Result<(), ProviderError> {
    let mut pending = vec![(current.to_path_buf(), 0_usize)];
    let mut current_root_ids = BTreeSet::new();
    while let Some((directory, depth)) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory).map_err(source_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ProviderError::InvalidState("Unsafe XDG application directory".into()));
        }
        let mut entries = fs::read_dir(&directory)
            .map_err(source_error)?
            .take(MAX_FILES + 1)
            .collect::<Result<Vec<_>, _>>()
            .map_err(source_error)?;
        if entries.len() > MAX_FILES {
            return Err(ProviderError::InvalidState("XDG directory entry budget exhausted".into()));
        }
        entries.sort_by_key(|item| item.file_name());
        // Traverse each directory deterministically regardless of filesystem order.
        for entry in entries.into_iter().rev() {
            let ty = entry.file_type().map_err(source_error)?;
            let path = entry.path();
            if ty.is_dir() {
                if depth >= MAX_DEPTH {
                    return Err(ProviderError::InvalidState("XDG application nesting limit".into()));
                }
                pending.push((path, depth + 1));
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "desktop") {
                continue;
            }
            if ty.is_symlink() || !ty.is_file() {
                return Err(ProviderError::InvalidState("Unsafe desktop source type".into()));
            }
            *files += 1;
            if *files > MAX_FILES {
                return Err(ProviderError::InvalidState("XDG application file count exceeds bound".into()));
            }
            let relative = path.strip_prefix(root).map_err(|_| {
                ProviderError::InvalidState("Desktop source escaped its XDG root".into())
            })?;
            let id = relative.to_str().ok_or_else(|| {
                ProviderError::InvalidState("Desktop source ID is not UTF-8".into())
            })?.replace('/', "-");
            if id.len() > 220 || id.is_empty() || id.chars().any(char::is_control) {
                return Err(ProviderError::InvalidState("Invalid desktop entry ID".into()));
            }
            if !current_root_ids.insert(id.clone()) {
                return Err(ProviderError::InvalidState("Ambiguous desktop entry ID in one root".into()));
            }
            if !seen.insert(id.clone()) {
                continue; // Higher-priority XDG source masks lower-priority sources.
            }
            let (bytes, uid) = read_desktop_source(&path)?;
            *total = total.checked_add(bytes.len()).ok_or_else(|| {
                ProviderError::InvalidState("XDG source byte count overflow".into())
            })?;
            if *total > MAX_TOTAL_BYTES {
                return Err(ProviderError::InvalidState("XDG inventory byte budget exhausted".into()));
            }
            let fields = parse_desktop_entry(&bytes)?;
            if fields.get("Type").map(String::as_str) != Some("Application") {
                continue;
            }
            let name = fields.get("Name").ok_or_else(|| {
                ProviderError::InvalidState("Application desktop entry has no Name".into())
            })?;
            if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
                return Err(ProviderError::InvalidState("Unsafe desktop application name".into()));
            }
            let hidden = parse_boolean(fields.get("Hidden"))?;
            let no_display = parse_boolean(fields.get("NoDisplay"))?;
            let terminal = parse_boolean(fields.get("Terminal"))?;
            let restricted = desktop_restricted(&fields, desktop);
            let digest = Sha256::digest(&bytes);
            sources.insert(id.clone(), DesktopSource {
                id,
                name: name.clone(),
                path,
                digest: format!("{digest:x}"),
                uid,
                root_priority: priority,
                hidden,
                no_display,
                terminal,
                try_exec_present: fields.contains_key("TryExec"),
                desktop_restricted: restricted,
            });
        }
    }
    Ok(())
}

fn source_error(_: std::io::Error) -> ProviderError {
    // Error strings can embed untrusted private paths; keep them out of logs/models.
    ProviderError::Unavailable("Cannot read XDG application sources".into())
}

fn read_desktop_source(path: &Path) -> Result<(Vec<u8>, u32), ProviderError> {
    // NOFOLLOW prevents a replaced final pathname from redirecting to a secret.
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ).map_err(|_| ProviderError::InvalidState("Unsafe desktop source open".into()))?;
    let mut file = File::from(fd);
    let before = file.metadata().map_err(source_error)?;
    if !before.is_file() || before.len() > MAX_FILE_BYTES as u64 {
        return Err(ProviderError::InvalidState("Desktop source is oversized or not regular".into()));
    }
    let mut bytes = Vec::new();
    file.by_ref().take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes).map_err(source_error)?;
    let after = file.metadata().map_err(source_error)?;
    let current_path = fs::symlink_metadata(path).map_err(source_error)?;
    if bytes.len() > MAX_FILE_BYTES
        || current_path.file_type().is_symlink()
        || (current_path.dev(), current_path.ino()) != (after.dev(), after.ino())
        || (before.dev(), before.ino(), before.len(), before.mtime(), before.mtime_nsec(), before.ctime(), before.ctime_nsec())
            != (after.dev(), after.ino(), after.len(), after.mtime(), after.mtime_nsec(), after.ctime(), after.ctime_nsec())
    {
        return Err(ProviderError::InvalidState("Desktop source changed during observation".into()));
    }
    Ok((bytes, after.uid()))
}

fn parse_desktop_entry(bytes: &[u8]) -> Result<BTreeMap<String, String>, ProviderError> {
    let contents = std::str::from_utf8(bytes).map_err(|_| {
        ProviderError::InvalidState("Non-UTF8 desktop source".into())
    })?;
    let mut in_entry = false;
    let mut entry_seen = false;
    let mut fields = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(ProviderError::InvalidState("Malformed desktop group".into()));
            }
            in_entry = line == "[Desktop Entry]";
            if in_entry {
                if entry_seen {
                    return Err(ProviderError::InvalidState("Duplicate Desktop Entry group".into()));
                }
                entry_seen = true;
            }
            continue;
        }
        if !in_entry {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            ProviderError::InvalidState("Malformed desktop entry assignment".into())
        })?;
        if ["Type", "Name", "Hidden", "NoDisplay", "Terminal", "TryExec", "OnlyShowIn", "NotShowIn"].contains(&key) {
            if fields.insert(key.into(), value.into()).is_some() {
                return Err(ProviderError::InvalidState("Duplicate desktop entry key".into()));
            }
        }
    }
    if !entry_seen {
        return Err(ProviderError::InvalidState("Missing Desktop Entry group".into()));
    }
    Ok(fields)
}

fn parse_boolean(value: Option<&String>) -> Result<bool, ProviderError> {
    match value.map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(ProviderError::InvalidState("Invalid desktop boolean".into())),
    }
}

fn desktop_restricted(fields: &BTreeMap<String, String>, desktop: Option<&str>) -> bool {
    let current = desktop.unwrap_or("").split(':').filter(|item| !item.is_empty())
        .collect::<BTreeSet<_>>();
    let matches_current = |key: &str| {
        fields.get(key).is_some_and(|value| {
            value.split(';').filter(|item| !item.is_empty())
                .any(|item| current.contains(item))
        })
    };
    (fields.contains_key("OnlyShowIn") && !matches_current("OnlyShowIn"))
        || matches_current("NotShowIn")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("linura-s23-xdg-{}-{n}", std::process::id()));
        if let Err(err) = fs::create_dir_all(root.join("applications")) {
            unreachable!("{err}");
        }
        root
    }

    #[test]
    fn precedence_masks_hidden_and_prevents_lower_source_retarget() {
        let first = fixture();
        let second = fixture();
        let high = first.join("applications/editor.desktop");
        let low = second.join("applications/editor.desktop");
        assert!(fs::write(&high, b"[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true\nExec=/bin/false\n").is_ok());
        assert!(fs::write(&low, b"[Desktop Entry]\nType=Application\nName=Other\nExec=/bin/true\n").is_ok());
        let observer = XdgApplicationObserver::for_test(vec![first.clone(), second.clone()], None);
        let resource = XdgApplicationObserver::exact_resource("editor.desktop").unwrap_or_else(|e| unreachable!("{e}"));
        let capability = CapabilityId::new(CAPABILITY).unwrap_or_else(|e| unreachable!("{e}"));
        let observation = observer.observe_authoritative(&resource, &capability).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(observation.attributes.get("hidden"), Some(&ObservedValue::Bool(true)));
        assert_eq!(observation.attributes.get("launch_authorized"), Some(&ObservedValue::Bool(false)));
        assert_eq!(observation.attributes.get("name"), Some(&ObservedValue::Text("Hidden".into())));
        assert!(!format!("{:?}", observation.attributes).contains("/bin/false"));
        let _ = fs::remove_dir_all(first);
        let _ = fs::remove_dir_all(second);
    }

    #[test]
    fn malformed_sources_do_not_become_incomplete_authoritative_catalog() {
        let root = fixture();
        let path = root.join("applications/other.desktop");
        assert!(fs::write(&path, b"[Desktop Entry]\nType=Application\nName=First\nName=Second\n").is_ok());
        let observer = XdgApplicationObserver::for_test(vec![root.clone()], None);
        assert!(matches!(observer.resources(), Err(ProviderError::InvalidState(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_group_and_invalid_visibility_are_rejected() {
        for invalid in [
            b"Type=Application\nName=Orphan\n".as_slice(),
            b"[Desktop Entry\nType=Application\nName=Broken\n".as_slice(),
            b"[Desktop Entry]\nType=Application\nName=First\n[Desktop Entry]\nName=Second\n".as_slice(),
            b"[Desktop Entry]\nType=Application\nName=App\nNoDisplay=maybe\n".as_slice(),
        ] {
            let parsed = parse_desktop_entry(invalid);
            match parsed {
                Ok(fields) => assert!(parse_boolean(fields.get("NoDisplay")).is_err()),
                Err(ProviderError::InvalidState(_)) => {},
                Err(error) => unreachable!("{error}"),
            }
        }
    }

    #[test]
    fn exact_source_change_and_unknown_capability_are_not_accepted() {
        let root = fixture();
        let path = root.join("applications/editor.desktop");
        assert!(fs::write(&path, b"[Desktop Entry]\nType=Application\nName=Editor\n").is_ok());
        let observer = XdgApplicationObserver::for_test(vec![root.clone()], Some("Hyprland"));
        let resource = XdgApplicationObserver::exact_resource("editor.desktop").unwrap_or_else(|e| unreachable!("{e}"));
        let cap = CapabilityId::new(CAPABILITY).unwrap_or_else(|e| unreachable!("{e}"));
        let original = observer.observe_authoritative(&resource, &cap).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(fs::write(&path, b"[Desktop Entry]\nType=Application\nName=Editor2\n").is_ok());
        let changed = observer.observe_authoritative(&resource, &cap).unwrap_or_else(|e| unreachable!("{e}"));
        assert_ne!(original.attributes.get("source_sha256"), changed.attributes.get("source_sha256"));
        let wrong = CapabilityId::new("desktop.package.install").unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(observer.observe_authoritative(&resource, &wrong), Err(ProviderError::Unsupported(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_private_source_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = fixture();
        let secret = root.join("private");
        assert!(fs::write(&secret, b"[Desktop Entry]\nType=Application\nName=Private\n").is_ok());
        assert!(symlink(&secret, root.join("applications/evil.desktop")).is_ok());
        let observer = XdgApplicationObserver::for_test(vec![root.clone()], None);
        assert!(matches!(observer.resources(), Err(ProviderError::InvalidState(_))));
        let _ = fs::remove_dir_all(root);
    }
}
