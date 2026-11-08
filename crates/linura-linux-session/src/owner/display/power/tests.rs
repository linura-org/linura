use super::*;
use rustix::fs::{self, FileType, Mode, OFlags};

fn value<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|e| unreachable!("{e:?}"))
}
struct Pipe {
    path: std::path::PathBuf,
    read: OwnedFd,
    write: OwnedFd,
}
impl Pipe {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "linura-display-fence-{}-{label}",
            std::process::id()
        ));
        value(fs::mknodat(
            fs::CWD,
            &path,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            fs::makedev(0, 0),
        ));
        let read = value(fs::open(
            &path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let write = value(fs::open(
            &path,
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        Self { path, read, write }
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        value(std::fs::remove_file(&self.path));
    }
}

#[test]
fn loss_of_either_real_fifo_peer_permanently_invalidates_the_lease() {
    for (label, read_end) in [("read", true), ("write", false)] {
        let pipe = Pipe::new(label);
        let retained = value(rustix::io::fcntl_dupfd_cloexec(
            if read_end { &pipe.read } else { &pipe.write },
            3,
        ));
        let mut lease = Lease {
            fd: retained,
            valid: true,
        };
        assert!(lease.verify().is_ok());
        // Close both original ends; only the retained side survives.
        drop(pipe);
        assert!(lease.verify().is_err());
        assert!(!lease.valid);
        assert!(lease.verify().is_err());
    }
}

#[test]
fn unexpected_data_cannot_be_drained_to_revive_a_failed_inhibitor() {
    let pipe = Pipe::new("data");
    let mut lease = Lease {
        fd: value(rustix::io::fcntl_dupfd_cloexec(&pipe.read, 3)),
        valid: true,
    };
    assert!(lease.verify().is_ok());
    value(rustix::io::write(&pipe.write, b"unexpected"));
    assert!(lease.verify().is_err());
    let mut bytes = [0; 32];
    value(rustix::io::read(&pipe.read, &mut bytes));
    assert!(lease.verify().is_err());
}

#[test]
fn lost_peer_cannot_be_reopened_to_renew_the_original_fifo_lifetime() {
    let mut pipe = Pipe::new("reopen");
    let mut lease = Lease {
        fd: value(rustix::io::fcntl_dupfd_cloexec(&pipe.read, 3)),
        valid: true,
    };
    assert!(lease.verify().is_ok());
    // A separate read descriptor can observe a writer disconnect/reconnect;
    // it must stay invalid even when a later poll again appears quiet.
    let writer = std::mem::replace(
        &mut pipe.write,
        value(rustix::io::fcntl_dupfd_cloexec(&pipe.read, 3)),
    );
    drop(writer);
    assert!(lease.verify().is_err());
    let _new_writer = value(fs::open(
        &pipe.path,
        OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ));
    assert!(lease.verify().is_err());
}

#[test]
fn non_fifo_and_non_cloexec_handles_never_become_protection() {
    let regular = value(fs::open(
        "/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ));
    assert!(
        Lease {
            fd: regular,
            valid: true
        }
        .verify()
        .is_err()
    );
    let pipe = Pipe::new("flags");
    let fd = value(rustix::io::fcntl_dupfd_cloexec(&pipe.read, 3));
    value(rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::empty()));
    let mut lease = Lease { fd, valid: true };
    assert!(lease.verify().is_err());
    value(rustix::io::fcntl_setfd(
        &lease.fd,
        rustix::io::FdFlags::CLOEXEC,
    ));
    assert!(lease.verify().is_err());
}

#[test]
fn preparation_missing_unknown_and_wrong_types_fail_closed() {
    use zbus::zvariant::OwnedValue;
    for (sleep, shutdown) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut fields = std::collections::HashMap::from([
            ("PreparingForSleep".to_owned(), OwnedValue::from(sleep)),
            (
                "PreparingForShutdown".to_owned(),
                OwnedValue::from(shutdown),
            ),
        ]);
        assert_eq!(not_preparing(&fields).is_ok(), !sleep && !shutdown);
        fields.remove("PreparingForSleep");
        assert!(not_preparing(&fields).is_err());
        fields.insert("PreparingForSleep".into(), OwnedValue::from(0u32));
        assert!(not_preparing(&fields).is_err());
    }
    let mut fields =
        std::collections::HashMap::from([("PreparingForSleep".into(), OwnedValue::from(false))]);
    assert!(not_preparing(&fields).is_err());
    fields.insert("PreparingForShutdown".into(), OwnedValue::from(0u32));
    assert!(not_preparing(&fields).is_err());
}

#[test]
fn protection_debug_never_exports_native_owner_boot_or_descriptor() {
    let pipe = Pipe::new("debug");
    let fence = NativeDisplayPowerFence {
        owner: ":1.42".into(),
        boot: value(linura_core::BootId::new(
            "11111111-1111-4111-8111-111111111111",
        )),
        lease: Lease {
            fd: value(rustix::io::fcntl_dupfd_cloexec(&pipe.read, 3)),
            valid: true,
        },
    };
    assert_eq!(format!("{fence:?}"), "NativeDisplayPowerFence { .. }");
}
