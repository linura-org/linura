//! Fixed-image attestation after supervisor/logind admission. Caller text never
//! chooses a file or an arbitrary process; the parent admits the session leader
//! and retains its original pidfd before invoking this mechanism.
use std::fs::{File, Metadata};
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
            && self.mode & 0o6022 == 0
            && self.mode & 0o100 != 0
            && (1..=512 * 1024 * 1024).contains(&self.size)
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
        Self::from_installed(pid, &installed, expected)
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
    ) -> Result<Self, String> {
        let started = Instant::now();
        let identity = Identity::new(&installed.metadata().map_err(|_| unavailable())?);
        if !identity.valid() {
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
        retained.live(pid)?;
        Ok(retained)
    }
    /// Metadata-only revalidation: hashing is performed once per admission,
    /// never again inside ongoing lease/input checks. The held immutable inode
    /// and a fresh kernel exe descriptor must still agree in every field.
    pub(super) fn live(&self, pid: u32) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Stdio;

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
        for mode in [
            0o100775, 0o100757, 0o104755, 0o102755, 0o040755, 0o010755, 0o100644,
        ] {
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
        let result = NativeDisplayImage::from_installed(pid, &installed, &expected);
        // Always reap the fixture even when an assertion fails.
        let wrong = NativeDisplayImage::from_installed(
            pid,
            &installed,
            &ComponentDigest::from_bytes([0; 32]),
        );
        let different = File::open("/usr/bin/true").unwrap_or_else(|e| unreachable!("{e}"));
        let substituted = NativeDisplayImage::from_installed(pid, &different, &expected);
        child.kill().unwrap_or_else(|e| unreachable!("{e}"));
        child.wait().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(wrong.is_err() && substituted.is_err());
        let retained = result.unwrap_or_else(|e| unreachable!("{e}"));
        assert!(retained.live(pid).is_err());
    }

    #[test]
    fn exec_in_the_same_live_pid_invalidates_the_retained_image() {
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", "import os,sys; sys.stdin.buffer.read(1); os.execv('/usr/bin/sleep', ['sleep', '30'])"])
            .stdin(Stdio::piped()).spawn().unwrap_or_else(|e| unreachable!("{e}"));
        let pid = child.id();
        let ticks = super::super::super::process_start(pid).unwrap_or_else(|e| unreachable!("{e}"));
        let image = NativeDisplayImage::test_process(pid);
        assert!(image.live(pid).is_ok());
        child
            .stdin
            .take()
            .unwrap_or_else(|| unreachable!())
            .write_all(b"1")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let started = Instant::now();
        while image.live(pid).is_ok() && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let changed = image.live(pid).is_err();
        let fresh_ticks = super::super::super::process_start(pid);
        child.kill().unwrap_or_else(|e| unreachable!("{e}"));
        child.wait().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(changed);
        assert_eq!(fresh_ticks, Ok(ticks)); // No exit or PID replacement explains refusal.
    }
}
