//! Bounded kernel mount-namespace attestation for the *actual* bus peer.
//!
//! A caller's PID must first be authenticated independently by the system-bus
//! kernel credentials and live logind session. This is a **read-only,
//! non-authorizing** corroboration and proves neither global mount quiescence
//! nor authority to mutate the kernel or UDisks2.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use linura_provider_sdk::ProviderError;

use crate::removable_storage_kernel::{KernelMountView, parse_mountinfo, sample_kernel_mountinfo};

const MAX_PROC_STAT_BYTES: u64 = 4096;
const MAX_PROC_MOUNTINFO_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountNamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyCallerMountNamespace {
    pub caller_pid: u32,
    pub caller_process_start_ticks: u64,
    pub namespace: MountNamespaceIdentity,
    pub mount_view: KernelMountView,
}

fn invalid(reason: &str) -> ProviderError {
    ProviderError::InvalidState(reason.into())
}

fn read_bounded(path: &Path, bound: u64) -> Result<String, ProviderError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| invalid("required live process mount evidence is unavailable"))?
        .take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("cannot read live process mount evidence"))?;
    if bytes.len() as u64 > bound {
        return Err(invalid("live process mount evidence exceeds its bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("live process mount evidence is not UTF-8"))
}

fn namespace_identity(metadata: &Metadata) -> MountNamespaceIdentity {
    MountNamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn read_namespace(path: &Path) -> Result<MountNamespaceIdentity, ProviderError> {
    let metadata =
        fs::metadata(path).map_err(|_| invalid("mount namespace identity is unavailable"))?;
    let namespace = namespace_identity(&metadata);
    if namespace.device == 0 || namespace.inode == 0 {
        return Err(invalid("mount namespace has invalid device or inode"));
    }
    Ok(namespace)
}

/// Parse /proc/<pid>/stat with the comm field surrounded by parentheses:
/// that field may contain spaces, so a whitespace-only split is unsafe.
/// Field 22 is starttime; after the closing parenthesis field 3 is index 0.
fn parse_start_ticks(stat: &str, expected_pid: u32) -> Result<u64, ProviderError> {
    let prefix = format!("{expected_pid} (");
    if expected_pid == 0 || !stat.starts_with(&prefix) {
        return Err(invalid("process stat PID is inconsistent"));
    }
    let close = stat
        .rfind(") ")
        .ok_or_else(|| invalid("process stat command boundary is missing"))?;
    let after = &stat[close + 2..];
    let fields: Vec<_> = after.split_whitespace().collect();
    if fields.len() < 20 || matches!(fields[0], "Z" | "X" | "x") {
        return Err(invalid("process is exited or its identity is incomplete"));
    }
    let start = fields[19];
    if start.is_empty() || start.len() > 20 || !start.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("process generation is not a bounded integer"));
    }
    let ticks = start
        .parse::<u64>()
        .map_err(|_| invalid("process generation overflows"))?;
    if ticks == 0 {
        return Err(invalid("process generation is absent"));
    }
    Ok(ticks)
}

fn review_same_namespace(
    caller: MountNamespaceIdentity,
    observer: MountNamespaceIdentity,
    caller_view: &KernelMountView,
    observer_view: &KernelMountView,
) -> Result<(), ProviderError> {
    if caller != observer || caller_view != observer_view {
        return Err(invalid(
            "authenticated user and authority have different mount namespace or mount state",
        ));
    }
    Ok(())
}

/// Prove that the observed process still has the same start generation and
/// namespace as the reading authority process. Other mount namespaces are
/// deliberately **unsupported** until a broader independently qualified
/// cross-namespace mount ownership/busy-writer verifier exists.
///
/// This witness does not permit any action, and must be revalidated by the
/// actual final user-session executor; it is not a PID lease or open PIDFD.
pub fn inspect_same_mount_namespace(
    authenticated_peer_pid: u32,
) -> Result<ReadOnlyCallerMountNamespace, ProviderError> {
    if authenticated_peer_pid == 0 {
        return Err(invalid(
            "mount namespace requires an authenticated positive PID",
        ));
    }
    let base = format!("/proc/{authenticated_peer_pid}");
    let stat_path = format!("{base}/stat");
    let namespace_path = format!("{base}/ns/mnt");
    let mountinfo_path = format!("{base}/mountinfo");

    let before = parse_start_ticks(
        &read_bounded(Path::new(&stat_path), MAX_PROC_STAT_BYTES)?,
        authenticated_peer_pid,
    )?;
    let caller_ns = read_namespace(Path::new(&namespace_path))?;
    let observer_ns = read_namespace(Path::new("/proc/self/ns/mnt"))?;
    if caller_ns != observer_ns {
        return Err(invalid("authenticated caller's mount namespace differs"));
    }
    let caller_view = parse_mountinfo(&read_bounded(
        Path::new(&mountinfo_path),
        MAX_PROC_MOUNTINFO_BYTES,
    )?)?;
    let observer_view = sample_kernel_mountinfo()?;
    let caller_ns_after = read_namespace(Path::new(&namespace_path))?;
    let observer_ns_after = read_namespace(Path::new("/proc/self/ns/mnt"))?;
    let after = parse_start_ticks(
        &read_bounded(Path::new(&stat_path), MAX_PROC_STAT_BYTES)?,
        authenticated_peer_pid,
    )?;
    if before != after || caller_ns != caller_ns_after || observer_ns != observer_ns_after {
        return Err(invalid(
            "authenticated caller generation or mount namespace changed during the read",
        ));
    }
    review_same_namespace(caller_ns, observer_ns, &caller_view, &observer_view)?;
    Ok(ReadOnlyCallerMountNamespace {
        caller_pid: authenticated_peer_pid,
        caller_process_start_ticks: before,
        namespace: caller_ns,
        mount_view: caller_view,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pid: u32, start: u64, command: &str) -> String {
        let mut parts = vec!["S".to_owned()];
        parts.extend((0..18).map(|_| "0".to_owned()));
        parts.push(start.to_string());
        format!("{pid} ({command}) {}", parts.join(" "))
    }

    #[test]
    fn process_identity_parser_handles_spaced_names_and_pid_substitution() {
        let fixture = stat(451, 9_876_543, "my strange) command");
        assert_eq!(parse_start_ticks(&fixture, 451), Ok(9_876_543));
        assert!(parse_start_ticks(&fixture, 452).is_err());
        assert!(parse_start_ticks(&stat(451, 0, "test"), 451).is_err());
        assert!(parse_start_ticks("451 (missing boundary", 451).is_err());
        assert!(parse_start_ticks("0 (test) S", 0).is_err());
    }

    #[test]
    fn namespace_and_mount_state_must_both_match() {
        let ns = MountNamespaceIdentity {
            device: 4,
            inode: 57,
        };
        let mut view = KernelMountView {
            mount_points_by_device: Default::default(),
        };
        assert!(review_same_namespace(ns, ns, &view, &view).is_ok());
        assert!(
            review_same_namespace(
                ns,
                MountNamespaceIdentity {
                    device: 4,
                    inode: 58,
                },
                &view,
                &view,
            )
            .is_err()
        );
        let original = view.clone();
        view.mount_points_by_device.insert(
            2049,
            std::collections::BTreeSet::from(["/media/usb".into()]),
        );
        assert!(review_same_namespace(ns, ns, &original, &view).is_err());
    }

    #[test]
    fn untrusted_zero_pid_never_selects_ambient_process() {
        assert!(inspect_same_mount_namespace(0).is_err());
    }
}
