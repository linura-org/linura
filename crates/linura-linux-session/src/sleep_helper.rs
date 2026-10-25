//! Fixed pre-sleep process entry only. Drop privilege before creating a native
//! connection; this helper carries no secret, executor permit or effect handle.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;

const HELPER: &str = "/usr/lib/linura/linura-executor-session";
const ARGUMENT: &str = "--protect-before-sleep";
const STATUS_LIMIT: usize = 16 * 1024;
const STATUS_FIELDS: [&str; 9] = [
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapAmb",
    "NoNewPrivs",
    "Threads",
];

pub(crate) fn enter_unprivileged() -> Result<(), String> {
    let (uid, gid) = crate::account::local_authority_ids()?;
    crate::sleep_gate::require_helper_process(std::process::id())?;
    let mut bytes = Vec::new();
    File::open("/proc/self/status")
        .map_err(|_| "native sleep helper credentials are unavailable")?
        .take((STATUS_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "native sleep helper credentials cannot be read")?;
    let fields = status_fields(&bytes)?;
    if fields.get("Threads") != Some(&"1") {
        return Err("native sleep helper must enter before runtime threads".into());
    }
    let real = rustix::process::getuid();
    let effective = rustix::process::geteuid();
    if real.is_root() || effective.is_root() {
        if !real.is_root() || !effective.is_root() {
            return Err("native sleep helper root entry is inconsistent".into());
        }
        rustix::thread::set_no_new_privs(true)
            .map_err(|_| "native sleep helper cannot prevent privilege acquisition")?;
        // Fixed self-exec only: no caller-selected program, account, arguments
        // or environment. uid() also clears supplementary groups. exec keeps
        // the PID/start generation and native ExecStartPre supervision, and
        // makes this ordinary non-setuid image inspectable at the new UID.
        let _ = Command::new(HELPER)
            .arg(ARGUMENT)
            .env_clear()
            .gid(gid)
            .uid(uid)
            .exec();
        return Err("native sleep helper could not enter its fixed unprivileged identity".into());
    }
    validate_unprivileged_status(&fields, uid, gid)
}

fn status_fields(bytes: &[u8]) -> Result<BTreeMap<&str, &str>, String> {
    let denied = || "native sleep helper credential facts are unsupported".to_owned();
    if bytes.len() > STATUS_LIMIT {
        return Err(denied());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| denied())?;
    let mut fields = BTreeMap::new();
    for (key, value) in text.lines().filter_map(|line| line.split_once(':')) {
        if STATUS_FIELDS.contains(&key) && fields.insert(key, value.trim()).is_some() {
            return Err(denied());
        }
    }
    if fields.len() != STATUS_FIELDS.len() {
        return Err(denied());
    }
    Ok(fields)
}

fn validate_unprivileged_status(
    fields: &BTreeMap<&str, &str>,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let user = uid.to_string();
    let group = gid.to_string();
    let ids = |key: &str, expected: &str| {
        fields
            .get(key)
            .is_some_and(|value| value.split_whitespace().eq([expected; 4]))
    };
    if uid == 0
        || gid == 0
        || !ids("Uid", &user)
        || !ids("Gid", &group)
        || fields.get("Groups") != Some(&"")
        || fields.get("NoNewPrivs") != Some(&"1")
        || fields.get("Threads") != Some(&"1")
        || ["CapInh", "CapPrm", "CapEff", "CapAmb"].iter().any(|key| {
            fields.get(key).is_none_or(|value| {
                value.is_empty() || value.len() > 16 || value.bytes().any(|byte| byte != b'0')
            })
        })
    {
        return Err("native sleep helper has not dropped every reusable privilege".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> Vec<u8> {
        b"Name:\thelper\nUid:\t991\t991\t991\t991\nGid:\t992\t992\t992\t992\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nThreads:\t1\n".to_vec()
    }

    #[test]
    fn helper_entry_requires_no_saved_root_groups_capabilities_or_future_privilege_gain() {
        let bytes = status();
        let fields = status_fields(&bytes).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(validate_unprivileged_status(&fields, 991, 992).is_ok());
        for (key, value) in [
            ("Uid", "0 991 991 991"),
            ("Uid", "991 0 991 991"),
            ("Uid", "991 991 0 991"),
            ("Uid", "991 991 991 0"),
            ("Uid", "0991 991 991 991"),
            ("Uid", "991 991 991"),
            ("Gid", "992 992 0 992"),
            ("Gid", "992 992 992 0"),
            ("Groups", "0"),
            ("Groups", "992"),
            ("CapInh", "0000000000000001"),
            ("CapPrm", "0000000000000001"),
            ("CapEff", "0000000000000001"),
            ("CapAmb", "0000000000000001"),
            ("CapEff", "unknown"),
            ("NoNewPrivs", "0"),
            ("Threads", "2"),
        ] {
            let mut bad = fields.clone();
            bad.insert(key, value);
            assert!(
                validate_unprivileged_status(&bad, 991, 992).is_err(),
                "{key}"
            );
        }
        for (uid, gid) in [(0, 992), (991, 0), (990, 992), (991, 990)] {
            assert!(validate_unprivileged_status(&fields, uid, gid).is_err());
        }
        for key in STATUS_FIELDS {
            let mut missing = fields.clone();
            missing.remove(key);
            assert!(validate_unprivileged_status(&missing, 991, 992).is_err());
        }
    }

    #[test]
    fn helper_status_is_bounded_complete_and_unambiguous() {
        assert!(status_fields(&[]).is_err());
        assert!(status_fields(&[0xff]).is_err());
        assert!(status_fields(&vec![b'0'; STATUS_LIMIT + 1]).is_err());
        let mut duplicate = status();
        duplicate.extend_from_slice(b"Uid: 991 991 991 991\n");
        assert!(status_fields(&duplicate).is_err());
        for key in STATUS_FIELDS {
            let missing = String::from_utf8(status())
                .unwrap_or_else(|error| unreachable!("{error}"))
                .lines()
                .filter(|line| !line.starts_with(&format!("{key}:")))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(status_fields(missing.as_bytes()).is_err(), "{key}");
        }
    }
}
