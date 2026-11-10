//! S18-6 bounded native resolver-configuration diagnostic.
//! /etc/resolv.conf is NOT proof of NSS, effective split DNS, upstream DNS,
//! per-link resolver routing, or connectivity. This never grants an effect.
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use linura_provider_sdk::ProviderError;
use sha2::{Digest, Sha256};

const CONFIG_LIMIT: u64 = 16 * 1024;
const MAX_SERVERS: usize = 16;
const MAX_LINES: usize = 256;
const PROBE_BUDGET: Duration = Duration::from_millis(250);

fn deny(reason: &str) -> ProviderError {
    ProviderError::InvalidState(format!("radio resolver {reason}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResolverMode {
    ResolvedStub,
    ResolvedUplink,
    NetworkManager,
    Static,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolverSnapshot {
    mode: ResolverMode,
    path: PathBuf,
    inode: u64,
    mtime: (i64, i64),
    digest: [u8; 32],
    servers: Vec<IpAddr>,
}

impl ResolverSnapshot {
    /// The resolver implementation must not be substituted during readback.
    /// Source continuity never proves *effective* split DNS.
    pub(super) fn require_same_source(&self, next: &Self) -> Result<(), ProviderError> {
        // Do not silently accept an unverified DNS update as a verified radio
        // transition. A future effective per-domain resolver oracle must
        // supersede this conservative source-generation equality.
        if self.mode != next.mode
            || self.path != next.path
            || self.inode != next.inode
            || self.mtime != next.mtime
            || self.digest != next.digest
            || self.servers != next.servers
        {
            return Err(deny("resolver source or content changed"));
        }
        Ok(())
    }

    #[must_use]
    pub(super) const fn proves_effective_split_dns(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            mode: ResolverMode::ResolvedStub,
            path: PathBuf::from("/run/systemd/resolve/stub-resolv.conf"),
            inode: 42,
            mtime: (1, 2),
            digest: [3; 32],
            servers: vec![],
        }
    }
}

fn root_owned(meta: &fs::Metadata) -> bool {
    meta.uid() == 0 && meta.mode() & 0o022 == 0
}

fn source() -> Result<(PathBuf, ResolverMode), ProviderError> {
    let entry = Path::new("/etc/resolv.conf");
    let link = fs::symlink_metadata(entry).map_err(|_| deny("entry inaccessible"))?;
    if link.uid() != 0 || (!link.file_type().is_symlink() && !root_owned(&link)) {
        return Err(deny("entry owner or mode is unsafe"));
    }
    let entry_parent = fs::metadata("/etc").map_err(|_| deny("resolver parent unavailable"))?;
    if !entry_parent.is_dir() || !root_owned(&entry_parent) {
        return Err(deny("resolver parent is mutable"));
    }
    let target = fs::canonicalize(entry).map_err(|_| deny("target inaccessible"))?;
    let mode = match target.to_str() {
        Some("/run/systemd/resolve/stub-resolv.conf") => ResolverMode::ResolvedStub,
        Some("/run/systemd/resolve/resolv.conf") => ResolverMode::ResolvedUplink,
        Some("/run/NetworkManager/resolv.conf") => ResolverMode::NetworkManager,
        Some("/etc/resolv.conf") if link.is_file() => ResolverMode::Static,
        _ => return Err(deny("unrecognized resolver source")),
    };
    let parent = target
        .parent()
        .ok_or_else(|| deny("missing source parent"))?;
    let parent_meta = fs::metadata(parent).map_err(|_| deny("parent inaccessible"))?;
    let target_meta = fs::metadata(&target).map_err(|_| deny("target inaccessible"))?;
    if !parent_meta.is_dir()
        || !root_owned(&parent_meta)
        || !target_meta.is_file()
        || !root_owned(&target_meta)
        || target_meta.nlink() != 1
    {
        return Err(deny("resolver source or parent is mutable"));
    }
    Ok((target, mode))
}

fn parse(text: &str) -> Result<Vec<IpAddr>, ProviderError> {
    let mut servers = Vec::new();
    let mut unique = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_LINES {
            return Err(deny("too many resolver lines"));
        }
        let statement = line.split(['#', ';']).next().unwrap_or("").trim();
        if statement.is_empty() {
            continue;
        }
        let parts: Vec<_> = statement.split_ascii_whitespace().collect();
        match parts.as_slice() {
            ["nameserver", address] => {
                let ip: IpAddr = address.parse().map_err(|_| deny("invalid nameserver"))?;
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || !unique.insert(ip)
                    || servers.len() >= MAX_SERVERS
                {
                    return Err(deny("duplicate, unusable or excessive nameserver"));
                }
                servers.push(ip);
            }
            ["search", domains @ ..] if !domains.is_empty() && domains.len() <= 16 => {
                for domain in domains {
                    if domain.len() > 253
                        || domain.is_empty()
                        || domain.bytes().any(|b| !b.is_ascii_graphic())
                    {
                        return Err(deny("invalid search domain"));
                    }
                }
            }
            ["domain", domain] if !domain.is_empty() && domain.len() <= 253 => {}
            ["options", options @ ..] if !options.is_empty() && options.len() <= 16 => {}
            _ => return Err(deny("unknown or unsafe resolver directive")),
        }
    }
    if servers.is_empty() {
        return Err(deny("no resolver servers"));
    }
    Ok(servers)
}

fn read(path: &Path) -> Result<(String, fs::Metadata), ProviderError> {
    let file = File::open(path).map_err(|_| deny("file open failed"))?;
    let before = file
        .metadata()
        .map_err(|_| deny("file metadata unavailable"))?;
    if !root_owned(&before) || before.len() > CONFIG_LIMIT {
        return Err(deny("file owner or size changed"));
    }
    let mut bytes = Vec::new();
    file.take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| deny("file read failed"))?;
    let after = fs::metadata(path).map_err(|_| deny("file disappeared"))?;
    if bytes.len() as u64 > CONFIG_LIMIT
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(deny("resolver replaced during read"));
    }
    Ok((
        String::from_utf8(bytes).map_err(|_| deny("non-UTF8 resolver configuration"))?,
        before,
    ))
}

pub(super) fn sample() -> Result<ResolverSnapshot, ProviderError> {
    let started = Instant::now();
    let (path, mode) = source()?;
    let (first, before) = read(&path)?;
    let servers = parse(&first)?;
    let (second, after) = read(&path)?;
    if source()? != (path.clone(), mode)
        || started.elapsed() >= PROBE_BUDGET
        || first != second
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(deny("resolver changed across independent snapshots"));
    }
    let mut digest = Sha256::new();
    digest.update(b"linura.s18-6.resolver-source.v1");
    digest.update(path.as_os_str().as_encoded_bytes());
    digest.update(first.as_bytes());
    Ok(ResolverSnapshot {
        mode,
        path,
        inode: before.ino(),
        mtime: (before.mtime(), before.mtime_nsec()),
        digest: digest.finalize().into(),
        servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_resolver_source_is_never_effective_dns_proof() {
        let first = ResolverSnapshot::fixture();
        assert!(!first.proves_effective_split_dns());
        assert!(first.require_same_source(&first).is_ok());
        let mut different = first.clone();
        different.mode = ResolverMode::NetworkManager;
        assert!(first.require_same_source(&different).is_err());
        different = first.clone();
        different.path = PathBuf::from("/run/systemd/resolve/resolv.conf");
        assert!(first.require_same_source(&different).is_err());
        different = first.clone();
        different.digest[0] = 9;
        assert!(first.require_same_source(&different).is_err());
        different = first.clone();
        different.servers.push(
            "127.0.0.53"
                .parse()
                .unwrap_or_else(|error| unreachable!("known DNS IP: {error}")),
        );
        assert!(first.require_same_source(&different).is_err());
    }

    #[test]
    fn resolver_parser_rejects_ambiguous_inputs() {
        assert_eq!(
            parse("# comment\nnameserver 127.0.0.53\nsearch local.example\noptions edns0\n")
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            1
        );
        for text in [
            "",
            "search example.com",
            "nameserver nonsense",
            "nameserver ::",
            "nameserver 0.0.0.0",
            "nameserver 8.8.8.8\nnameserver 8.8.8.8",
            "nameserver 224.0.0.1",
            "nameserver 8.8.8.8\nsortlist 10.0.0.0/8",
            "nameserver 8.8.8.8\nmalicious directive",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
}
