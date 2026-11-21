//! Bounded local identity for fixed native services; never NSS or caller input.
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::owner::immutable_file;

const ACCOUNT_LIMIT: u64 = 256 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum LocalServiceAccount {
    Authority,
    Polkit,
}

pub(crate) fn local_service_uid(account: LocalServiceAccount) -> Result<u32, String> {
    parse_service_uid(account, &local_accounts()?)
}

pub(crate) fn local_authority_ids() -> Result<(u32, u32), String> {
    parse_authority_ids(&local_accounts()?)
}

fn local_accounts() -> Result<Vec<u8>, String> {
    local_database(Path::new("/etc/passwd"))
}

pub(crate) fn local_display_entry_gid() -> Result<u32, String> {
    let gid = parse_display_entry_gid(&local_database(Path::new("/etc/group"))?)?;
    validate_display_entry_accounts(gid, &local_accounts()?)?;
    Ok(gid)
}

fn validate_display_entry_accounts(gid: u32, bytes: &[u8]) -> Result<(), String> {
    let denied = || "native display entry group has unsupported primary membership".to_owned();
    if bytes.len() as u64 > ACCOUNT_LIMIT {
        return Err(denied());
    }
    for line in std::str::from_utf8(bytes)
        .map_err(|_| denied())?
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(denied());
        }
        let primary: u32 = fields[3].parse().map_err(|_| denied())?;
        if primary.to_string() != fields[3] || primary == gid {
            return Err(denied());
        }
    }
    Ok(())
}

fn parse_display_entry_gid(bytes: &[u8]) -> Result<u32, String> {
    let denied = || "native display entry group is absent, shared or unsupported".to_owned();
    if bytes.len() as u64 > ACCOUNT_LIMIT {
        return Err(denied());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| denied())?;
    let mut selected = None;
    let mut all = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 4 {
            return Err(denied());
        }
        let gid: u32 = fields[2].parse().map_err(|_| denied())?;
        if gid.to_string() != fields[2] {
            return Err(denied());
        }
        all.push(gid);
        if fields[0] == "linura-display-entry" {
            if selected.is_some() || gid == 0 || gid == u32::MAX || !fields[3].is_empty() {
                return Err(denied());
            }
            selected = Some(gid);
        }
    }
    let gid = selected.ok_or_else(denied)?;
    if all.iter().filter(|&&other| other == gid).count() != 1 {
        return Err(denied());
    }
    Ok(gid)
}

fn local_database(path: &Path) -> Result<Vec<u8>, String> {
    if !immutable_file(path, false) {
        return Err("local service account database is not immutable".into());
    }
    let flags = i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
        .map_err(|_| "local service account open flags are unsupported")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|_| "local service account database is unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "local service account metadata is unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > ACCOUNT_LIMIT
    {
        return Err("local service account database is unsupported".into());
    }
    let mut bytes = Vec::new();
    file.take(ACCOUNT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "local service account database cannot be read")?;
    Ok(bytes)
}

fn parse_authority_ids(bytes: &[u8]) -> Result<(u32, u32), String> {
    let uid = parse_service_uid(LocalServiceAccount::Authority, bytes)?;
    // The UID parser already requires exactly one complete canonical account.
    // Read its primary group from the SAME descriptor-bound byte snapshot.
    let group = bytes
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(b"linura-authority:"))
        .and_then(|line| line.split(|byte| *byte == b':').nth(3))
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or("local authority group is unsupported")?;
    let gid: u32 = group
        .parse()
        .map_err(|_| "local authority group is unsupported")?;
    if uid == u32::MAX || gid == 0 || gid == u32::MAX || gid.to_string() != group {
        return Err("local authority group is unsupported".into());
    }
    Ok((uid, gid))
}

fn parse_service_uid(account: LocalServiceAccount, bytes: &[u8]) -> Result<u32, String> {
    let denied = || "local service account is absent, ambiguous or unsupported".to_owned();
    if bytes.len() as u64 > ACCOUNT_LIMIT {
        return Err(denied());
    }
    std::str::from_utf8(bytes).map_err(|_| denied())?;
    let prefix = match account {
        LocalServiceAccount::Authority => b"linura-authority:".as_slice(),
        LocalServiceAccount::Polkit => b"polkitd:".as_slice(),
    };
    let mut uid = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| line.starts_with(prefix))
    {
        let fields: Vec<_> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 7 || uid.is_some() {
            return Err(denied());
        }
        let text = std::str::from_utf8(fields[2]).map_err(|_| denied())?;
        let parsed: u32 = text.parse().map_err(|_| denied())?;
        if parsed == 0 || parsed.to_string() != text {
            return Err(denied());
        }
        uid = Some(parsed);
    }
    uid.ok_or_else(denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_entry_group_is_local_unique_non_root_and_has_no_members() {
        let good = "root:x:0:\nlinura-display-entry:x:991:\nother:x:992:user\n";
        assert_eq!(parse_display_entry_gid(good.as_bytes()), Ok(991));
        for bad in [
            "",
            "linura-display-entry:x:0:\n",
            "linura-display-entry:x:0991:\n",
            "linura-display-entry:x:4294967295:\n",
            "linura-display-entry:x:991:user\n",
            "linura-display-entry:x:991:\nother:x:991:\n",
            "linura-display-entry:x:991:\nlinura-display-entry:x:992:\n",
            "linura-display-entry:x:991\n",
            "another:x:991:\n",
        ] {
            assert!(parse_display_entry_gid(bad.as_bytes()).is_err());
        }
        assert!(parse_display_entry_gid(&vec![b'x'; ACCOUNT_LIMIT as usize + 1]).is_err());
        assert!(
            validate_display_entry_accounts(
                991,
                b"root:x:0:0::/:/bin/bash\nuser:x:1000:1000::/:/bin/bash\n"
            )
            .is_ok()
        );
        for bad in [
            b"user:x:1000:991::/:/bin/bash\n".as_slice(),
            b"user:x:1000:0991::/:/bin/bash\n",
            b"user:x:1000:garbled::/:/bin/bash\n",
            b"user:x:1000:4294967296::/:/bin/bash\n",
            b"user:x:1000:1000\n",
            b"\xff",
        ] {
            assert!(validate_display_entry_accounts(991, bad).is_err());
        }
    }
    #[test]
    fn helper_identity_requires_the_same_exact_non_root_account_and_primary_group() {
        assert_eq!(
            parse_authority_ids(b"linura-authority:x:991:992::/:/usr/bin/nologin\n"),
            Ok((991, 992))
        );
        for group in ["", "0", "0992", "+992", " 992", "4294967295", "4294967296"] {
            assert!(
                parse_authority_ids(
                    format!("linura-authority:x:991:{group}::/:/usr/bin/nologin\n").as_bytes()
                )
                .is_err()
            );
        }
        for invalid in [
            "linura-authority:x:0:992::/:/usr/bin/nologin\n",
            "linura-authority:x:4294967295:992::/:/usr/bin/nologin\n",
            "other:x:991:992::/:/usr/bin/nologin\n",
            "linura-authority:x:991:992::/:/usr/bin/nologin\nlinura-authority:x:991:992::/:/usr/bin/nologin\n",
        ] {
            assert!(parse_authority_ids(invalid.as_bytes()).is_err());
        }
    }
    #[test]
    fn service_identity_never_comes_from_nss_alias_or_duplicate_account() {
        assert_eq!(
            parse_service_uid(
                LocalServiceAccount::Authority,
                b"linura-authority:x:991:991::/:/usr/bin/nologin"
            ),
            Ok(991)
        );
        for contents in [
            "",
            "linura-authority:x:0:0::/:/bin/sh",
            "linura-authority:x:0991:991::/:/bin/sh",
            "linura-authority:x:991",
            "linura-authority:x:991:991::/:/bin/sh\nlinura-authority:x:992:992::/:/bin/sh",
        ] {
            assert!(
                parse_service_uid(LocalServiceAccount::Authority, contents.as_bytes()).is_err()
            );
        }
    }
    #[test]
    fn local_polkit_account_is_exact_non_root_bounded_and_unambiguous() {
        assert_eq!(
            parse_service_uid(
                LocalServiceAccount::Polkit,
                b"root:x:0:0::/:/bin/sh\npolkitd:x:102:102::/:/usr/bin/nologin\n"
            ),
            Ok(102)
        );
        for invalid in [
            b"".as_slice(),
            b"another:x:102:102::/:/bin/false\n",
            b"polkitd:x:0:0::/:/bin/false\n",
            b"polkitd:x:0102:102::/:/bin/false\n",
            b"polkitd:x:+102:102::/:/bin/false\n",
            b"polkitd:x: 102:102::/:/bin/false\n",
            b"polkitd:x:4294967296:102::/:/bin/false\n",
            b"polkitd:x:102:102::/\n",
            b"polkitd:x:102:102::/:/bin/false\npolkitd:x:103:103::/:/bin/false\n",
            b"polkitd:x:\xff:102::/:/bin/false\n",
        ] {
            assert!(parse_service_uid(LocalServiceAccount::Polkit, invalid).is_err());
        }
        assert!(
            parse_service_uid(LocalServiceAccount::Polkit, &vec![b'x'; 256 * 1024 + 1]).is_err()
        );
    }
}
