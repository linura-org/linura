//! Read-only freedesktop MIME Apps configuration and ordered default candidates.
//! A candidate is not an effective associated handler: native desktop-entry
//! eligibility/association verification and qualified edits are separate work.
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
use rustix::fs::{open, Mode, OFlags};
use sha2::{Digest, Sha256};
use super::{capability, next_sequence, now_unix_ms, provider_id};

const PROVIDER: &str = "xdg-mimeapps";
const CAPABILITY: &str = "xdg.mime.association.observe";
const RESOURCE_PREFIX: &str = "xdg:mime:";
const MAX_PATHS: usize = 96;
const MAX_FILE_BYTES: usize = 512 * 1024;
const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 8192;
const FRESH_MS: u64 = 1000;

#[derive(Clone, Debug)]
struct MimeSource {
    path: PathBuf,
    desktop_specific: bool,
}

#[derive(Clone, Debug, Default)]
struct MimeEntry {
    defaults: Vec<String>,
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Clone, Debug)]
struct MimeSnapshot {
    effective_candidates: BTreeMap<String, Vec<(usize, String)>>,
    revision: String,
    source_count: usize,
}

#[derive(Debug)]
pub struct XdgMimeAppsObserver {
    paths: Vec<MimeSource>,
    environment_error: Option<String>,
    sequence: AtomicU64,
}

impl XdgMimeAppsObserver {
    #[must_use]
    pub fn from_environment() -> Self {
        match current_paths() {
            Ok(paths) => Self {
                paths,
                environment_error: None,
                sequence: AtomicU64::new(0),
            },
            Err(error) => Self {
                paths: Vec::new(),
                environment_error: Some(error),
                sequence: AtomicU64::new(0),
            },
        }
    }

    #[cfg(test)]
    fn for_test(paths: Vec<(PathBuf, bool)>) -> Self {
        Self {
            paths: paths.into_iter().map(|(path, desktop_specific)| MimeSource {
                path, desktop_specific,
            }).collect(),
            environment_error: None,
            sequence: AtomicU64::new(0),
        }
    }

    fn inventory(&self) -> Result<MimeSnapshot, ProviderError> {
        if let Some(error) = &self.environment_error {
            return Err(ProviderError::Unavailable(error.clone()));
        }
        if self.paths.len() > MAX_PATHS {
            return Err(invalid("XDG MIME search path count exceeds bound"));
        }
        let mut hash = Sha256::new();
        let mut entries = BTreeMap::<String, Vec<(usize, String)>>::new();
        let mut total = 0_usize;
        let mut sources = 0_usize;
        let mut unique = BTreeSet::new();
        for (index, source) in self.paths.iter().enumerate() {
            if !unique.insert(source.path.clone()) {
                return Err(invalid("XDG MIME search path is duplicated"));
            }
            let Some(bytes) = read_mime_file(&source.path)? else {
                continue;
            };
            sources += 1;
            total = total.checked_add(bytes.len()).ok_or_else(|| invalid("MIME byte budget overflow"))?;
            if total > MAX_TOTAL_BYTES {
                return Err(invalid("XDG MIME source budget exhausted"));
            }
            // Length-delimit each path and source; source order is part of the revision.
            let location = source.path.to_str().ok_or_else(|| invalid("MIME file path not UTF-8"))?;
            hash.update((location.len() as u64).to_be_bytes());
            hash.update(location.as_bytes());
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(&bytes);
            let parsed = parse_mime_file(&bytes, source.desktop_specific)?;
            for (mime, entry) in parsed {
                let bucket=entries.entry(mime).or_default();
                for id in entry.defaults {
                    bucket.push((index,id));
                }
                // Added/Removed are parsed strictly but never misreported as
                // effective associations without the desktop entry source scan.
                let _ = (entry.added,entry.removed);
            }
            if entries.len() > MAX_ITEMS {
                return Err(invalid("XDG MIME catalog has too many types"));
            }
        }
        Ok(MimeSnapshot {
            effective_candidates: entries,
            revision: format!("{:x}", hash.finalize()),
            source_count: sources,
        })
    }

    fn resource(mime: &str) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!("{RESOURCE_PREFIX}{mime}"))
            .map_err(|_| invalid("XDG MIME resource exceeds typed identifier bound"))
    }
}

impl Observer for XdgMimeAppsObserver {
    fn observer_id(&self) -> ProviderId { provider_id(PROVIDER) }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health=self.health();
        vec![capability(CAPABILITY, PROVIDER, health.availability, health.reason)]
    }

    fn health(&self) -> ProviderHealth {
        let ready=self.environment_error.is_none();
        ProviderHealth {
            provider: provider_id(PROVIDER),
            availability: if ready { ProviderAvailability::Available } else { ProviderAvailability::Unavailable },
            reason: self.environment_error.clone(),
        }
    }

    fn requires_live_health_preflight(&self) -> bool {
        false // Exact snapshot reads all current available files.
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.inventory()?.effective_candidates.keys().map(|mime| Self::resource(mime)).collect()
    }

    fn observe_authoritative(
        &self, resource: &ResourceId, cap: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if cap.as_str()!=CAPABILITY {
            return Err(ProviderError::Unsupported("Not a MIME configuration observation".into()));
        }
        let mime=resource.as_str().strip_prefix(RESOURCE_PREFIX)
            .ok_or_else(|| ProviderError::Unsupported("Not a MIME resource".into()))?;
        if !canonical_mime(mime) || Self::resource(mime)?.as_str()!=resource.as_str() {
            return Err(invalid("Invalid MIME resource"));
        }
        let snapshot=self.inventory()?;
        let candidates=snapshot.effective_candidates.get(mime);
        let first=candidates.and_then(|v| v.first());
        Ok(ObservationEnvelope {
            provider: provider_id(PROVIDER), resource: resource.clone(), capability: cap.clone(),
            authority: ObservationAuthority::Filesystem,
            observed_at_unix_ms: now_unix_ms()?, valid_for_ms: FRESH_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("mime_type".into(), ObservedValue::Text(mime.into())),
                ("candidate_desktop_id".into(), ObservedValue::Text(first.map_or("", |v| v.1.as_str()).into())),
                ("candidate_source_priority".into(), ObservedValue::U64(first.map_or(0, |v| v.0 as u64))),
                ("candidate_count".into(), ObservedValue::U64(candidates.map_or(0, |v| v.len() as u64))),
                ("config_revision_sha256".into(), ObservedValue::Text(snapshot.revision)),
                ("source_file_count".into(), ObservedValue::U64(snapshot.source_count as u64)),
                ("effective_handler_verified".into(), ObservedValue::Bool(false)),
                ("association_verified".into(), ObservedValue::Bool(false)),
                ("effect_authorized".into(), ObservedValue::Bool(false)),
            ]),
        })
    }
}

fn invalid(problem: &'static str) -> ProviderError { ProviderError::InvalidState(problem.into()) }
fn source_error(_: std::io::Error) -> ProviderError {
    ProviderError::Unavailable("Cannot securely read XDG MIME configuration".into())
}
fn canonical_mime(mime:&str) -> bool {
    mime.len() <= 180 && !mime.is_empty() && mime.split_once('/').is_some_and(|(major,minor)|{
        !major.is_empty() && !minor.is_empty() &&
        major.bytes().chain(minor.bytes()).all(|b|
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
    })
}
fn canonical_id(id:&str) -> bool {
    id.ends_with(".desktop") && id.len() <= 220
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn parse_ids(value:&str) -> Result<Vec<String>, ProviderError> {
    if value.len()>16384 || (!value.is_empty() && !value.ends_with(';')) {
        return Err(invalid("Invalid XDG desktop ID list encoding"));
    }
    let mut ids=Vec::new();
    let mut seen=BTreeSet::new();
    for id in value.split(';').filter(|id| !id.is_empty()) {
        if !canonical_id(id) || !seen.insert(id) || ids.len()>=256 {
            return Err(invalid("Duplicate or unsafe MIME desktop ID"));
        }
        ids.push(id.into());
    }
    Ok(ids)
}
fn parse_mime_file(bytes:&[u8], desktop_specific:bool)-> Result<BTreeMap<String,MimeEntry>,ProviderError> {
    let text=std::str::from_utf8(bytes).map_err(|_| invalid("XDG MIME configuration is not UTF-8"))?;
    let mut section="";
    let mut visited=BTreeSet::new();
    let mut out=BTreeMap::<String,MimeEntry>::new();
    let mut used=BTreeSet::new();
    for line in text.lines() {
        let line=line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.starts_with('[') {
            if !line.ends_with(']') || !visited.insert(line.to_owned()) {
                return Err(invalid("Malformed or duplicated MIME INI group"));
            }
            section=match line {
                "[Default Applications]"=>"defaults",
                "[Added Associations]"=>"added",
                "[Removed Associations]"=>"removed",
                _=>"ignore",
            };
            if desktop_specific && (section=="added" || section=="removed") {
                return Err(invalid("Desktop-specific MIME file cannot change associations"));
            }
            continue;
        }
        if section=="ignore" { continue; }
        if section.is_empty() { return Err(invalid("MIME assignment outside group")); }
        let (mime,value)=line.split_once('=').ok_or_else(|| invalid("Malformed MIME assignment"))?;
        if !canonical_mime(mime) || !used.insert((section.to_owned(),mime.to_owned())) {
            return Err(invalid("Invalid or duplicate MIME association key"));
        }
        let ids=parse_ids(value)?;
        let entry=out.entry(mime.into()).or_default();
        match section {
            "defaults"=>entry.defaults=ids,
            "added"=>entry.added=ids,
            "removed"=>entry.removed=ids,
            _=>return Err(invalid("Unexpected MIME parse group")),
        }
        if out.len()>MAX_ITEMS { return Err(invalid("MIME file has too many types")); }
    }
    for (mime,entry) in &out {
        let both=entry.added.iter().any(|id| entry.removed.contains(id));
        if both { return Err(invalid("Conflicting Added and Removed MIME associations")); }
        let _=mime;
    }
    Ok(out)
}

fn read_mime_file(path:&Path)->Result<Option<Vec<u8>>,ProviderError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(error)=>return Err(source_error(error)),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink()
            || meta.len()>MAX_FILE_BYTES as u64
            || meta.nlink()!=1 => return Err(invalid("Unsafe MIME config source")),
        Ok(_) => {}
    }
    let fd=open(path,OFlags::RDONLY|OFlags::CLOEXEC|OFlags::NOFOLLOW|OFlags::NONBLOCK,Mode::empty())
        .map_err(|_| invalid("MIME configuration path substituted"))?;
    let mut file=File::from(fd);
    let before=file.metadata().map_err(source_error)?;
    let mut bytes=Vec::new();
    file.by_ref().take((MAX_FILE_BYTES+1) as u64)
        .read_to_end(&mut bytes).map_err(source_error)?;
    let after=file.metadata().map_err(source_error)?;
    let path_after=fs::symlink_metadata(path).map_err(source_error)?;
    let revision=|m:&fs::Metadata| (m.dev(),m.ino(),m.len(),m.uid(),m.mode(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec());
    if bytes.len()>MAX_FILE_BYTES || bytes.len() as u64!=before.len()
        || !before.is_file() || before.nlink()!=1
        || path_after.file_type().is_symlink()
        || revision(&before)!=revision(&after) || revision(&after)!=revision(&path_after) {
        return Err(invalid("MIME configuration mutated during observation"));
    }
    Ok(Some(bytes))
}

fn absolute(raw:OsString)->Result<PathBuf,String> {
    let p=PathBuf::from(raw);
    if !p.is_absolute() || p.as_os_str().len()>2048 {
        return Err("XDG MIME directory is not a bounded absolute path".into());
    }
    Ok(p)
}

fn current_paths()->Result<Vec<MimeSource>,String> {
    let home=absolute(env::var_os("HOME").ok_or("HOME unavailable for MIME configuration")?)?;
    let config_home=env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty())
        .map_or_else(|| Ok(home.join(".config")),absolute)?;
    let data_home=env::var_os("XDG_DATA_HOME").filter(|x| !x.is_empty())
        .map_or_else(|| Ok(home.join(".local/share")),absolute)?;
    let list_dirs=|value:Option<OsString>,default:&str| -> Result<Vec<PathBuf>,String> {
        let dirs=value.unwrap_or_else(|| OsString::from(default));
        let text=dirs.to_str().ok_or("XDG MIME path list is not UTF-8")?;
        text.split(':').map(|s| {
            if s.is_empty(){Err("Empty XDG MIME search directory".into())}
            else {absolute(OsString::from(s))}
        }).collect()
    };
    let config_dirs=list_dirs(env::var_os("XDG_CONFIG_DIRS").filter(|v| !v.is_empty()),"/etc/xdg")?;
    let data_dirs=list_dirs(env::var_os("XDG_DATA_DIRS").filter(|v| !v.is_empty()),"/usr/local/share:/usr/share")?;
    let desktop=env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let mut desktops=Vec::new();
    for v in desktop.split(':').filter(|s| !s.is_empty()) {
        if v.len()>64 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
            return Err("Unsafe XDG_CURRENT_DESKTOP component".into());
        }
        let v=v.to_ascii_lowercase();
        if !desktops.contains(&v) { desktops.push(v); }
    }
    let mut paths=Vec::new();
    let mut add_dir=|dir:PathBuf| {
        for name in &desktops {
            paths.push(MimeSource { path:dir.join(format!("{name}-mimeapps.list")), desktop_specific:true });
        }
        paths.push(MimeSource { path:dir.join("mimeapps.list"), desktop_specific:false });
    };
    add_dir(config_home);
    for dir in config_dirs { add_dir(dir); }
    add_dir(data_home.join("applications"));
    for dir in data_dirs { add_dir(dir.join("applications")); }
    if paths.len()>MAX_PATHS { return Err("XDG MIME source path budget exhausted".into()); }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64,Ordering};
    static NEXT:AtomicU64=AtomicU64::new(0);
    fn fixture()->PathBuf {
        let n=NEXT.fetch_add(1,Ordering::Relaxed);
        let dir=env::temp_dir().join(format!("linura-s23-mime-{}-{n}",std::process::id()));
        assert!(fs::create_dir_all(&dir).is_ok());
        dir
    }
    #[test]
    fn desktop_specific_candidate_precedes_generic_but_not_effective() {
        let dir=fixture();
        let desktop=dir.join("hyprland-mimeapps.list");
        let generic=dir.join("mimeapps.list");
        assert!(fs::write(&desktop,b"[Default Applications]\nx-scheme-handler/https=browser.desktop;\n").is_ok());
        assert!(fs::write(&generic,b"[Default Applications]\nx-scheme-handler/https=another.desktop;\n").is_ok());
        let observer=XdgMimeAppsObserver::for_test(vec![(desktop,true),(generic,false)]);
        let resource=XdgMimeAppsObserver::resource("x-scheme-handler/https").unwrap_or_else(|e| unreachable!("{e}"));
        let cap=CapabilityId::new(CAPABILITY).unwrap_or_else(|e| unreachable!("{e}"));
        let found=observer.observe_authoritative(&resource,&cap).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(found.attributes["candidate_desktop_id"],ObservedValue::Text("browser.desktop".into()));
        assert_eq!(found.attributes["candidate_count"],ObservedValue::U64(2));
        assert_eq!(found.attributes["effective_handler_verified"],ObservedValue::Bool(false));
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn symlink_and_conflicting_association_are_denied() {
        use std::os::unix::fs::symlink;
        let dir=fixture();
        let target=dir.join("real");
        let link=dir.join("mimeapps.list");
        assert!(fs::write(&target,b"[Default Applications]\nimage/png=a.desktop;\n").is_ok());
        assert!(symlink(&target,&link).is_ok());
        let observer=XdgMimeAppsObserver::for_test(vec![(link,false)]);
        assert!(matches!(observer.resources(),Err(ProviderError::InvalidState(_))));
        assert!(parse_mime_file(b"[Added Associations]\nimage/png=a.desktop;\n[Removed Associations]\nimage/png=a.desktop;\n",false).is_err());
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn missing_config_is_not_claimed_as_effective_handler() {
        let dir=fixture();
        let observer=XdgMimeAppsObserver::for_test(vec![(dir.join("missing"),false)]);
        let resource=XdgMimeAppsObserver::resource("image/png").unwrap_or_else(|e| unreachable!("{e}"));
        let cap=CapabilityId::new(CAPABILITY).unwrap_or_else(|e| unreachable!("{e}"));
        let result=observer.observe_authoritative(&resource,&cap).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(result.attributes["candidate_count"],ObservedValue::U64(0));
        assert_eq!(result.attributes["effect_authorized"],ObservedValue::Bool(false));
        let _=fs::remove_dir_all(dir);
    }
}
