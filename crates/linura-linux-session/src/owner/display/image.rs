//! Fixed-image attestation after supervisor/logind admission. Caller text never
//! chooses a file or an arbitrary process; the parent admits the session leader
//! and retains its original pidfd before invoking this mechanism.
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{Duration, Instant};

use linura_provider_sdk::ComponentDigest;
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

fn unavailable() -> String {
    "native executable attestation unavailable; ordinary presentation remains fenced".into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Identity {
    fn new(info: &Metadata) -> Self {
        Self {
            device: info.dev(),
            inode: info.ino(),
            mode: info.mode(),
            uid: info.uid(),
            gid: info.gid(),
            links: info.nlink(),
            size: info.size(),
            modified: (info.mtime(), info.mtime_nsec()),
            changed: (info.ctime(), info.ctime_nsec()),
        }
    }
    fn valid(&self) -> bool {
        self.mode & 0o170000 == 0o100000
            && self.uid == 0
            && self.links == 1
            && self.mode & 0o4022 == 0
            && self.mode & 0o100 != 0
            && (1..=512 * 1024 * 1024).contains(&self.size)
    }
    fn secure_entry(&self, expected_gid: u32) -> bool {
        self.valid()
            && expected_gid != 0
            && expected_gid != u32::MAX
            && self.gid == expected_gid
            && self.mode & 0o2000 != 0
    }
}

/// Process-local retained descriptor, not a serialized grant or authority.
#[derive(Debug)]
pub(super) struct NativeDisplayImage {
    image: File,
    identity: Identity,
}
impl NativeDisplayImage {
    #[cfg(test)]
    pub(super) fn test_process(pid: u32) -> Self {
        let installed = File::open("/usr/bin/python3").unwrap_or_else(|e| unreachable!("{e}"));
        let bytes = std::fs::read("/usr/bin/python3").unwrap_or_else(|e| unreachable!("{e}"));
        Self::from_installed(
            pid,
            &installed,
            &ComponentDigest::from_bytes(Sha256::digest(&bytes).into()),
            &Identity::new(&installed.metadata().unwrap_or_else(|e| unreachable!("{e}"))),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    pub(super) fn inspect(pid: u32, expected: &ComponentDigest) -> Result<Self, String> {
        let directory = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let mut parent: File = rustix::fs::open("/", directory, Mode::empty())
            .map_err(|_| unavailable())?
            .into();
        for child in ["usr", "bin"] {
            Self::directory(&parent)?;
            parent = rustix::fs::openat(&parent, child, directory, Mode::empty())
                .map_err(|_| unavailable())?
                .into();
        }
        Self::directory(&parent)?;
        let installed: File = rustix::fs::openat(
            &parent,
            "Hyprland",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| unavailable())?
        .into();
        let metadata = Identity::new(&installed.metadata().map_err(|_| unavailable())?);
        if !metadata.secure_entry(crate::account::local_display_entry_gid()?) {
            return Err(unavailable());
        }
        secure_entry(pid)?;
        let image = Self::from_installed(pid, &installed, expected, &metadata)?;
        image.live(pid)?;
        Ok(image)
    }
    fn directory(file: &File) -> Result<(), String> {
        let info = file.metadata().map_err(|_| unavailable())?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o22 != 0 {
            return Err(unavailable());
        }
        Ok(())
    }
    fn executing(pid: u32) -> Result<File, String> {
        // Follow only the kernel's virtual exe link for the admitted leader.
        rustix::fs::open(
            format!("/proc/{pid}/exe"),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| unavailable())
    }
    fn from_installed(
        pid: u32,
        installed: &File,
        expected: &ComponentDigest,
        admitted: &Identity,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let identity = Identity::new(&installed.metadata().map_err(|_| unavailable())?);
        // Bind the secure-entry metadata checked by the caller through image
        // capture and hashing; never silently adopt a later installation state.
        if &identity != admitted || !identity.valid() {
            return Err(unavailable());
        }
        let image = Self::executing(pid)?;
        if Identity::new(&image.metadata().map_err(|_| unavailable())?) != identity {
            return Err(unavailable()); // Never hash an unadmitted image.
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 65_536];
        let mut consumed = 0_u64;
        loop {
            // Hash the already-open trusted installed descriptor after exact
            // executing-inode equality. Never read another process's memory or
            // an untrusted executable's contents; pread leaves offsets intact.
            let size = installed
                .read_at(&mut buffer, consumed)
                .map_err(|_| unavailable())?;
            if started.elapsed() >= Duration::from_secs(1) {
                return Err(unavailable());
            }
            if size == 0 {
                break;
            }
            consumed = consumed.checked_add(size as u64).ok_or_else(unavailable)?;
            if consumed > identity.size {
                return Err(unavailable());
            }
            hash.update(&buffer[..size]);
        }
        if consumed != identity.size
            || &ComponentDigest::from_bytes(hash.finalize().into()) != expected
            || Identity::new(&installed.metadata().map_err(|_| unavailable())?) != identity
        {
            return Err(unavailable());
        }
        let retained = Self { image, identity };
        retained.live_identity(pid)?;
        Ok(retained)
    }
    /// Metadata-only revalidation: hashing is performed once per admission,
    /// never again inside ongoing lease/input checks. The held immutable inode
    /// and a fresh kernel exe descriptor must still agree in every field.
    pub(super) fn live(&self, pid: u32) -> Result<(), String> {
        self.live_identity(pid)?;
        secure_entry(pid)
    }
    fn live_identity(&self, pid: u32) -> Result<(), String> {
        if Identity::new(&self.image.metadata().map_err(|_| unavailable())?) != self.identity
            || Identity::new(
                &Self::executing(pid)?
                    .metadata()
                    .map_err(|_| unavailable())?,
            ) != self.identity
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

fn secure_entry(pid: u32) -> Result<(), String> {
    let file: File = rustix::fs::open(
        format!("/proc/{pid}/auxv"),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| unavailable())?
    .into();
    let mut bytes = Vec::new();
    file.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if !secure_auxv(&bytes) {
        return Err(unavailable());
    }
    Ok(())
}

fn secure_auxv(bytes: &[u8]) -> bool {
    // This source-pinned Linux compositor requires a native 64-bit ABI.
    if usize::BITS != 64
        || bytes.is_empty()
        || bytes.len() > 1024
        || !bytes.len().is_multiple_of(16)
    {
        return false;
    }
    let mut keys = std::collections::BTreeSet::new();
    let mut secure = false;
    for (index, pair) in bytes.as_chunks::<16>().0.iter().enumerate() {
        let Ok(key) = <[u8; 8]>::try_from(&pair[..8]) else {
            return false;
        };
        let Ok(value) = <[u8; 8]>::try_from(&pair[8..]) else {
            return false;
        };
        let key = u64::from_ne_bytes(key);
        let value = u64::from_ne_bytes(value);
        if !keys.insert(key) {
            return false;
        }
        if key == 0 {
            return value == 0 && secure && (index + 1) * 16 == bytes.len();
        }
        if key == 23 {
            if value != 1 {
                return false;
            }
            secure = true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Stdio;

    #[test]
    fn secure_exec_auxiliary_vector_is_kernel_shaped_unique_complete_and_bounded() {
        let wire = |pairs: &[(u64, u64)]| -> Vec<u8> {
            pairs
                .iter()
                .flat_map(|(key, value)| key.to_ne_bytes().into_iter().chain(value.to_ne_bytes()))
                .collect()
        };
        let good = wire(&[(6, 4096), (23, 1), (0, 0)]);
        assert!(secure_auxv(&good));
        for end in 0..good.len() {
            assert!(!secure_auxv(&good[..end]));
        }
        for pairs in [
            vec![(23, 0), (0, 0)],
            vec![(23, 2), (0, 0)],
            vec![(6, 4096), (0, 0)],
            vec![(23, 1)],
            vec![(23, 1), (23, 1), (0, 0)],
            vec![(23, 1), (0, 1)],
            vec![(23, 1), (0, 0), (6, 4096)],
            vec![(23, 1), (6, 1), (6, 2), (0, 0)],
        ] {
            assert!(!secure_auxv(&wire(&pairs)));
        }
        assert!(!secure_auxv(&vec![0; 1025]));
    }

    #[test]
    fn executable_identity_rejects_mutable_special_linked_or_unbounded_files() {
        let original = Identity {
            device: 1,
            inode: 2,
            mode: 0o100755,
            uid: 0,
            gid: 0,
            links: 1,
            size: 123,
            modified: (1, 2),
            changed: (3, 4),
        };
        assert!(original.valid());
        let secure = Identity {
            mode: 0o102755,
            gid: 991,
            ..original.clone()
        };
        assert!(secure.secure_entry(991));
        assert!(!secure.secure_entry(992));
        assert!(!secure.secure_entry(0));
        assert!(!secure.secure_entry(u32::MAX));
        assert!(!original.secure_entry(991));
        for mode in [
            0o100755, 0o106755, 0o102775, 0o102757, 0o042755, 0o012755, 0o102644,
        ] {
            assert!(
                !Identity {
                    mode,
                    ..secure.clone()
                }
                .secure_entry(991)
            );
        }
        for mode in [0o100775, 0o100757, 0o104755, 0o040755, 0o010755, 0o100644] {
            assert!(
                !Identity {
                    mode,
                    ..original.clone()
                }
                .valid()
            );
        }
        assert!(
            !Identity {
                uid: 1000,
                ..original.clone()
            }
            .valid()
        );
        for links in [0, 2] {
            assert!(
                !Identity {
                    links,
                    ..original.clone()
                }
                .valid()
            );
        }
        for size in [0, 512 * 1024 * 1024 + 1, u64::MAX] {
            assert!(
                !Identity {
                    size,
                    ..original.clone()
                }
                .valid()
            );
        }
    }

    #[test]
    fn retained_actual_executable_requires_exact_installed_bytes_and_original_process() {
        let installed = File::open("/usr/bin/python3").unwrap_or_else(|e| unreachable!("{e}"));
        let bytes = std::fs::read("/usr/bin/python3").unwrap_or_else(|e| unreachable!("{e}"));
        let expected = ComponentDigest::from_bytes(Sha256::digest(&bytes).into());
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", "import time; time.sleep(30)"])
            .spawn()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let pid = child.id();
        let admitted = Identity::new(&installed.metadata().unwrap_or_else(|e| unreachable!("{e}")));
        let result = NativeDisplayImage::from_installed(pid, &installed, &expected, &admitted);
        let mut changed_admission = admitted.clone();
        changed_admission.mode ^= 0o2000;
        let changed =
            NativeDisplayImage::from_installed(pid, &installed, &expected, &changed_admission);
        // Always reap the fixture even when an assertion fails.
        let wrong = NativeDisplayImage::from_installed(
            pid,
            &installed,
            &ComponentDigest::from_bytes([0; 32]),
            &admitted,
        );
        let different = File::open("/usr/bin/true").unwrap_or_else(|e| unreachable!("{e}"));
        let substituted = NativeDisplayImage::from_installed(pid, &different, &expected, &admitted);
        child.kill().unwrap_or_else(|e| unreachable!("{e}"));
        child.wait().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(wrong.is_err() && substituted.is_err() && changed.is_err());
        let retained = result.unwrap_or_else(|e| unreachable!("{e}"));
        assert!(retained.live_identity(pid).is_err());
    }

    #[test]
    fn exec_in_the_same_live_pid_invalidates_the_retained_image() {
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", "import os,sys; sys.stdin.buffer.read(1); os.execv('/usr/bin/sleep', ['sleep', '30'])"])
            .stdin(Stdio::piped()).spawn().unwrap_or_else(|e| unreachable!("{e}"));
        let pid = child.id();
        let ticks = super::super::super::process_start(pid).unwrap_or_else(|e| unreachable!("{e}"));
        let image = NativeDisplayImage::test_process(pid);
        assert!(image.live_identity(pid).is_ok());
        assert!(image.live(pid).is_err()); // Ordinary exec cannot satisfy secure admission.
        child
            .stdin
            .take()
            .unwrap_or_else(|| unreachable!())
            .write_all(b"1")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let started = Instant::now();
        while image.live_identity(pid).is_ok() && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let changed = image.live_identity(pid).is_err();
        let fresh_ticks = super::super::super::process_start(pid);
        child.kill().unwrap_or_else(|e| unreachable!("{e}"));
        child.wait().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(changed);
        assert_eq!(fresh_ticks, Ok(ticks)); // No exit or PID replacement explains refusal.
    }
}
