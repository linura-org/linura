//! Original system-bus caller binding for read-only backlight discovery.
//!
//! ProcessFD comes from the authenticated bus, never pidfd_open on a supplied
//! PID. Retaining it excludes PID recycling even if a descendant inherits the
//! original bus socket. This proves neither protected worker identity nor a
//! Control dispatch permit. Unsupported broker/kernel evidence fails closed.

use std::cell::Cell;
use std::future::Future;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::Serialize;
use zbus::zvariant::{DynamicType, Fd};

use super::*;

const MAX_SUBJECT_REPLY_BYTES: usize = 16 * 1024;
const MAX_FDINFO_BYTES: u64 = 4_096;

fn unavailable() -> ProviderError {
    ProviderError::Unavailable(
        "original backlight caller evidence is unavailable or expired".into(),
    )
}

fn invalid() -> ProviderError {
    ProviderError::InvalidState("original backlight caller evidence is inconsistent".into())
}

/// One conservative clock for connection, credentials, session and kernel reads.
/// BOOTTIME includes suspend; wall time additionally rejects clock regressions.
#[derive(Debug)]
struct ProbeClock {
    boot: Duration,
    unix_ms: u64,
    valid_for: Duration,
    last: Cell<(Duration, u64)>,
}

impl ProbeClock {
    fn start(budget: Duration) -> Result<Self, ProviderError> {
        let valid_for = budget.min(Duration::from_millis(VALID_FOR_MS));
        if valid_for.is_zero() {
            return Err(unavailable());
        }
        let boot = boot_time()?;
        let unix_ms = now_unix_ms()?;
        Ok(Self {
            boot,
            unix_ms,
            valid_for,
            last: Cell::new((boot, unix_ms)),
        })
    }

    fn remaining(&self) -> Result<Duration, ProviderError> {
        self.remaining_at(boot_time()?, now_unix_ms()?)
    }

    fn remaining_at(&self, boot: Duration, unix_ms: u64) -> Result<Duration, ProviderError> {
        let last = self.last.get();
        if boot < last.0 || unix_ms < last.1 {
            return Err(unavailable());
        }
        self.last.set((boot, unix_ms));
        let elapsed = boot.checked_sub(self.boot).ok_or_else(unavailable)?;
        let wall =
            Duration::from_millis(unix_ms.checked_sub(self.unix_ms).ok_or_else(unavailable)?);
        self.valid_for
            .checked_sub(elapsed.max(wall))
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(unavailable)
    }

    async fn wait<T>(
        &self,
        pending: impl Future<Output = Result<T, ProviderError>>,
    ) -> Result<T, ProviderError> {
        let start = (boot_time()?, now_unix_ms()?);
        let timeout = self
            .remaining_at(start.0, start.1)?
            .min(NATIVE_CALL_TIMEOUT);
        let result = futures_lite::future::race(pending, async {
            async_io::Timer::after(timeout).await;
            Err(unavailable())
        })
        .await;
        let end = (boot_time()?, now_unix_ms()?);
        self.remaining_at(end.0, end.1)?;
        require_elapsed(start, end, timeout)?;
        result
    }
}

fn require_elapsed(
    start: (Duration, u64),
    end: (Duration, u64),
    timeout: Duration,
) -> Result<(), ProviderError> {
    let boot = end.0.checked_sub(start.0).ok_or_else(unavailable)?;
    let wall = Duration::from_millis(end.1.checked_sub(start.1).ok_or_else(unavailable)?);
    if boot.max(wall) >= timeout {
        return Err(unavailable());
    }
    Ok(())
}

fn boot_time() -> Result<Duration, ProviderError> {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let secs = u64::try_from(time.tv_sec).map_err(|_| unavailable())?;
    let nanos = u32::try_from(time.tv_nsec).map_err(|_| unavailable())?;
    if nanos >= 1_000_000_000 {
        return Err(unavailable());
    }
    Ok(Duration::new(secs, nanos))
}

fn connect_observer(clock: &ProbeClock) -> Result<LogindSessionObserver, ProviderError> {
    let start = (boot_time()?, now_unix_ms()?);
    let connect_timeout = clock
        .remaining_at(start.0, start.1)?
        .min(NATIVE_CALL_TIMEOUT);
    let stream = crate::platform_discovery::connect_unix_with_deadline(
        Path::new("/run/dbus/system_bus_socket"),
        connect_timeout,
        "original backlight caller system bus",
    )
    .map_err(|_| unavailable())?;
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| unavailable())?;
    if peer.uid.as_raw() != 0 {
        return Err(invalid());
    }
    let end = (boot_time()?, now_unix_ms()?);
    clock.remaining_at(end.0, end.1)?;
    require_elapsed(start, end, connect_timeout)?;
    let builder = zbus::connection::Builder::async_io_unix_stream(stream)
        .method_timeout(NATIVE_CALL_TIMEOUT)
        .max_queued(64);
    let connection =
        async_io::block_on(clock.wait(async { builder.build().await.map_err(|_| unavailable()) }))?;
    clock.remaining()?;
    Ok(LogindSessionObserver {
        connection: Connection::from(connection),
        sequence: AtomicU64::new(0),
    })
}

// Preserve the broker dictionary's extensibility while rejecting duplicate
// fields and bounding entries during decoding, rather than after allocation.
#[derive(Debug, zbus::zvariant::Type)]
#[zvariant(signature = "a{sv}")]
struct BrokerCredentials(HashMap<String, OwnedValue>);

impl<'de> serde::Deserialize<'de> for BrokerCredentials {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = BrokerCredentials;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("bounded unique bus credentials")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = HashMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.len() >= 32 || key.len() > 128 || values.contains_key(&key) {
                        return Err(serde::de::Error::custom("invalid credential dictionary"));
                    }
                    values.insert(key, map.next_value::<OwnedValue>()?);
                }
                Ok(BrokerCredentials(values))
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

fn read_credentials(reply: &zbus::Message) -> Result<HashMap<String, OwnedValue>, ProviderError> {
    require_subject_reply(reply)?;
    reply
        .body()
        .deserialize::<BrokerCredentials>()
        .map(|value| value.0)
        .map_err(|_| invalid())
}

#[derive(Debug)]
struct CallerProcess {
    fd: OwnedFd,
    pid: u32,
}

impl CallerProcess {
    fn from_credentials(
        mut credentials: HashMap<String, OwnedValue>,
        expected_uid: u32,
        expected_pid: u32,
    ) -> Result<Self, ProviderError> {
        if credentials.len() > 32 {
            return Err(invalid());
        }
        let uid = u32::try_from(credentials.remove("UnixUserID").ok_or_else(unavailable)?)
            .map_err(|_| invalid())?;
        let pid = u32::try_from(credentials.remove("ProcessID").ok_or_else(unavailable)?)
            .map_err(|_| invalid())?;
        require_backlight_sender_credentials(uid, expected_uid, pid)?;
        if pid != expected_pid || pid > i32::MAX as u32 {
            return Err(invalid());
        }
        let fd = Fd::try_from(credentials.remove("ProcessFD").ok_or_else(unavailable)?)
            .map_err(|_| invalid())?;
        let process = Self {
            fd: fd.try_into().map_err(|_| invalid())?,
            pid,
        };
        process.require_live()?;
        Ok(process)
    }

    fn require_live(&self) -> Result<(), ProviderError> {
        // A zero-time poll never waits, retries, signals or inspects user data.
        let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
        if poll(&mut fds, Some(&Timespec::default())).map_err(|_| unavailable())? != 0
            || !fds[0].revents().is_empty()
        {
            return Err(unavailable());
        }
        // Verify both that this really is a pidfd and that its live kernel PID
        // agrees with the bus-provided ProcessID. Numeric PID alone is unsafe.
        let path = format!("/proc/self/fdinfo/{}", self.fd.as_raw_fd());
        let fd = rustix::fs::open(
            path.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| unavailable())?;
        let file = File::from(fd);
        if rustix::fs::fstatfs(&file)
            .map_err(|_| unavailable())?
            .f_type
            != 0x9fa0
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_FDINFO_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        require_fdinfo_pid(&bytes, self.pid)
    }
}

fn require_fdinfo_pid(bytes: &[u8], expected: u32) -> Result<(), ProviderError> {
    if expected == 0 || expected > i32::MAX as u32 || bytes.len() as u64 > MAX_FDINFO_BYTES {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut pid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:\t") {
            if pid.is_some() || value != expected.to_string() {
                return Err(invalid());
            }
            pid = Some(expected);
        }
    }
    if pid != Some(expected) {
        return Err(invalid());
    }
    Ok(())
}

/// Adapter-local evidence retained across independent native reads. No public
/// client, model or executor receives this object or its process descriptor.
#[derive(Debug)]
pub(crate) struct BacklightSubjectProbe {
    observer: LogindSessionObserver,
    expected: SessionEpoch,
    sender: String,
    owner: String,
    process: CallerProcess,
    clock: ProbeClock,
}

impl BacklightSubjectProbe {
    pub(crate) fn connect(
        expected: &SessionEpoch,
        bus_guid: &str,
        sender: &str,
        pid: u32,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        if expected.uid() == 0
            || pid == 0
            || pid > i32::MAX as u32
            || zbus::names::UniqueName::try_from(sender).is_err()
        {
            return Err(invalid());
        }
        let clock = ProbeClock::start(budget)?;
        let observer = connect_observer(&clock)?;
        clock.remaining()?;
        require_bus_generation(bus_guid, observer.connection.server_guid())?;
        let bus = observer.bus()?;
        let reply = bounded_call(&clock, &bus, "GetConnectionCredentials", &(sender,))?;
        let process =
            CallerProcess::from_credentials(read_credentials(&reply)?, expected.uid(), pid)?;
        drop(bus);
        let owner = read_owner(&clock, &observer)?;
        let probe = Self {
            observer,
            expected: expected.clone(),
            sender: sender.into(),
            owner,
            process,
            clock,
        };
        probe.check()?;
        Ok(probe)
    }

    pub(crate) fn check(&self) -> Result<(), ProviderError> {
        self.clock.remaining()?;
        self.process.require_live()?;
        require_same_boot(self.expected.boot(), &current_boot()?)?;
        self.clock.remaining()?;
        Ok(())
    }

    pub(crate) fn observe(&self) -> Result<NativeBacklightSession, ProviderError> {
        self.check()?;
        let manager = self.observer.manager(&self.owner)?;
        let path: OwnedObjectPath = bounded_call(
            &self.clock,
            &manager,
            "GetSession",
            &(self.expected.session_id(),),
        )?
        .body()
        .deserialize()
        .map_err(|_| invalid())?;
        self.require_session_path(&manager, &path)?;
        let properties = Proxy::new(
            &self.observer.connection,
            self.owner.as_str(),
            path.as_str(),
            "org.freedesktop.DBus.Properties",
        )
        .map_err(|_| unavailable())?;
        let reply = bounded_call(&self.clock, &properties, "GetAll", &(SESSION_INTERFACE,))?;
        let values = reply.body().deserialize().map_err(|_| invalid())?;
        let session = SessionSnapshot::from_properties(&values, self.expected.boot().clone())?;
        require_backlight_session_scope(&session, self.expected.session_id(), self.expected.uid())?;
        require_same_epoch(&self.expected, &session.epoch)?;
        self.require_session_path(&manager, &path)?;
        // Recheck connection credentials, not only session labels: loss of the
        // original sender is failure even if an unrelated process has its UID.
        let reply = bounded_call(
            &self.clock,
            &self.observer.bus()?,
            "GetConnectionCredentials",
            &(self.sender.as_str(),),
        )?;
        let fresh = CallerProcess::from_credentials(
            read_credentials(&reply)?,
            self.expected.uid(),
            self.process.pid,
        )?;
        fresh.require_live()?;
        if read_owner(&self.clock, &self.observer)? != self.owner {
            return Err(invalid());
        }
        self.check()?;
        Ok(NativeBacklightSession {
            boot_id: self.expected.boot().as_str().into(),
            logind_owner: self.owner.clone(),
            session_id: self.expected.session_id().into(),
            created_monotonic_us: self.expected.created_monotonic_us(),
            seat_id: session.seat,
            uid: self.expected.uid(),
            // Retain original acquisition; later reads do not refresh freshness.
            observed_at_unix_ms: self.clock.unix_ms,
        })
    }

    fn require_session_path(
        &self,
        manager: &Proxy<'_>,
        expected: &OwnedObjectPath,
    ) -> Result<(), ProviderError> {
        let actual: OwnedObjectPath = bounded_call(
            &self.clock,
            manager,
            "GetSessionByPID",
            &(self.process.pid,),
        )?
        .body()
        .deserialize()
        .map_err(|_| invalid())?;
        require_backlight_sender_path(actual.as_str(), expected.as_str())
    }
}

fn require_bus_generation(expected: &str, actual: &str) -> Result<(), ProviderError> {
    if expected.len() != 32
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || expected != actual
    {
        return Err(invalid());
    }
    Ok(())
}

fn read_owner(
    clock: &ProbeClock,
    observer: &LogindSessionObserver,
) -> Result<String, ProviderError> {
    let bus = observer.bus()?;
    let owner: String = bounded_call(clock, &bus, "GetNameOwner", &(SERVICE,))?
        .body()
        .deserialize()
        .map_err(|_| invalid())?;
    let uid: u32 = bounded_call(clock, &bus, "GetConnectionUnixUser", &(owner.as_str(),))?
        .body()
        .deserialize()
        .map_err(|_| invalid())?;
    validate_owner(&owner, uid)?;
    Ok(owner)
}

fn bounded_call<B: Serialize + DynamicType>(
    clock: &ProbeClock,
    proxy: &Proxy<'_>,
    method: &str,
    body: &B,
) -> Result<zbus::Message, ProviderError> {
    let reply = async_io::block_on(clock.wait(async {
        proxy
            .inner()
            .call_method(method, body)
            .await
            .map_err(|_| unavailable())
    }))?;
    require_subject_reply(&reply)?;
    Ok(reply)
}

fn require_subject_reply(reply: &zbus::Message) -> Result<(), ProviderError> {
    if reply.body().len() > MAX_SUBJECT_REPLY_BYTES || reply.body().data().fds().len() > 4 {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restarted_bus_cannot_reuse_an_original_unique_sender() {
        let original = "0123456789abcdef0123456789abcdef";
        assert!(require_bus_generation(original, original).is_ok());
        for other in [
            "",
            ":1.42",
            "1123456789abcdef0123456789abcdef",
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(require_bus_generation(original, other).is_err());
            assert!(require_bus_generation(other, original).is_err());
        }
    }

    #[test]
    fn caller_budget_can_only_tighten_the_native_probe() {
        assert!(ProbeClock::start(Duration::ZERO).is_err());
        let capped = ProbeClock::start(Duration::MAX).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(capped.valid_for, Duration::from_secs(2));
        let clock = ProbeClock {
            boot: Duration::from_secs(10),
            unix_ms: 10_000,
            valid_for: Duration::from_millis(25),
            last: Cell::new((Duration::from_secs(10), 10_000)),
        };
        assert_eq!(
            clock
                .remaining_at(Duration::from_millis(10_024), 10_000)
                .ok(),
            Some(Duration::from_millis(1))
        );
        assert!(
            clock
                .remaining_at(Duration::from_millis(10_025), 10_000)
                .is_err()
        );
        assert!(clock.remaining_at(Duration::from_secs(10), 10_025).is_err());
    }

    #[test]
    fn partial_clock_regression_and_late_ready_reply_fail_closed() {
        let clock = ProbeClock {
            boot: Duration::from_secs(10),
            unix_ms: 10_000,
            valid_for: Duration::from_secs(2),
            last: Cell::new((Duration::from_secs(10), 10_000)),
        };
        assert!(
            clock
                .remaining_at(Duration::from_millis(10_100), 10_800)
                .is_ok()
        );
        assert!(
            clock
                .remaining_at(Duration::from_millis(10_200), 10_700)
                .is_err()
        );
        let start = (Duration::from_secs(10), 10_000);
        assert!(
            require_elapsed(
                start,
                (start.0 + NATIVE_CALL_TIMEOUT, start.1),
                NATIVE_CALL_TIMEOUT
            )
            .is_err()
        );
        assert!(require_elapsed(start, (start.0, 10_750), NATIVE_CALL_TIMEOUT).is_err());
        assert!(
            require_elapsed(
                start,
                (start.0 + Duration::from_millis(749), start.1),
                NATIVE_CALL_TIMEOUT
            )
            .is_ok()
        );
    }

    #[test]
    fn clock_never_renews_budget_and_accounts_for_suspend_and_wall_changes() {
        let clock = ProbeClock {
            boot: Duration::from_secs(10),
            unix_ms: 10_000,
            valid_for: Duration::from_secs(2),
            last: Cell::new((Duration::from_secs(10), 10_000)),
        };
        assert_eq!(
            clock.remaining_at(Duration::from_secs(10), 10_000).ok(),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            clock
                .remaining_at(Duration::from_millis(11_999), 10_000)
                .ok(),
            Some(Duration::from_millis(1))
        );
        for (boot, wall) in [
            (9_999, 10_000),
            (10_000, 9_999),
            (12_000, 10_000),
            (10_000, 12_000),
            (12_001, 12_001),
        ] {
            assert!(
                clock
                    .remaining_at(Duration::from_millis(boot), wall)
                    .is_err()
            );
        }
    }

    #[test]
    fn missing_recycled_forged_or_unbounded_pidfd_identity_is_not_evidence() {
        assert!(require_fdinfo_pid(b"pos:\t0\nPid:\t42\nNSpid:\t42\n", 42).is_ok());
        for bytes in [
            b"pos:\t0\n".as_slice(),
            b"Pid:\t-1\n",
            b"Pid:\t43\n",
            b"Pid:\t042\n",
            b"Pid:\t42\nPid:\t42\n",
            b"Pid:\t42 \n",
            b"Pid:\t\xff\n",
        ] {
            assert!(require_fdinfo_pid(bytes, 42).is_err());
        }
        assert!(require_fdinfo_pid(&vec![b'x'; MAX_FDINFO_BYTES as usize + 1], 42).is_err());
        assert!(require_fdinfo_pid(b"Pid:\t0\n", 0).is_err());
    }

    #[test]
    fn real_kernel_pidfd_is_live_then_permanently_invalid_after_process_exit() {
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let result = rustix::process::Pid::from_raw(child.id() as i32)
            .ok_or_else(invalid)
            .and_then(|pid| {
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                    .map_err(|_| unavailable())
            });
        let live = result.as_ref().ok().map(|fd| CallerProcess {
            fd: fd
                .try_clone()
                .unwrap_or_else(|error| unreachable!("{error}")),
            pid: child.id(),
        });
        let before = live.as_ref().map(CallerProcess::require_live);
        let _ = child.kill();
        let _ = child.wait();
        assert!(result.is_ok(), "native test requires kernel pidfd support");
        assert!(matches!(before, Some(Ok(()))));
        assert!(live.is_some_and(|process| process.require_live().is_err()));
    }

    fn credentials(uid: u32, pid: u32, fd: OwnedFd) -> HashMap<String, OwnedValue> {
        let value = OwnedValue::try_from(zbus::zvariant::Value::from(Fd::from(fd)))
            .unwrap_or_else(|error| unreachable!("{error}"));
        HashMap::from([
            ("UnixUserID".into(), OwnedValue::from(uid)),
            ("ProcessID".into(), OwnedValue::from(pid)),
            ("ProcessFD".into(), value),
        ])
    }

    #[test]
    fn broker_credentials_require_original_nonroot_uid_pid_and_live_processfd() {
        let pid = std::process::id();
        let native = rustix::process::Pid::from_raw(pid as i32)
            .unwrap_or_else(|| unreachable!("test process must have a PID"));
        let fd = || {
            rustix::process::pidfd_open(native, rustix::process::PidfdFlags::empty())
                .unwrap_or_else(|error| unreachable!("{error}"))
        };
        assert!(CallerProcess::from_credentials(credentials(1000, pid, fd()), 1000, pid).is_ok());
        let message = zbus::Message::method_call(MANAGER_PATH, "Fixture")
            .and_then(|builder| builder.build(&credentials(1000, pid, fd())))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            CallerProcess::from_credentials(
                read_credentials(&message).unwrap_or_else(|error| unreachable!("{error}")),
                1000,
                pid,
            )
            .is_ok()
        );
        for (actual_uid, expected_uid, actual_pid, expected_pid) in [
            (0, 1000, pid, pid),
            (0, 0, pid, pid),
            (1001, 1000, pid, pid),
            (1000, 1000, 0, pid),
            (1000, 1000, pid, 0),
            (1000, 1000, pid, pid + 1),
            (1000, 1000, pid + 1, pid + 1),
        ] {
            assert!(
                CallerProcess::from_credentials(
                    credentials(actual_uid, actual_pid, fd()),
                    expected_uid,
                    expected_pid,
                )
                .is_err()
            );
        }
        for missing in ["ProcessID", "UnixUserID", "ProcessFD"] {
            let mut values = credentials(1000, pid, fd());
            values.remove(missing);
            assert!(CallerProcess::from_credentials(values, 1000, pid).is_err());
        }
        for wrong in ["ProcessID", "UnixUserID", "ProcessFD"] {
            let mut values = credentials(1000, pid, fd());
            values.insert(wrong.into(), OwnedValue::from(true));
            assert!(CallerProcess::from_credentials(values, 1000, pid).is_err());
        }
        let mut excessive = credentials(1000, pid, fd());
        for n in 0..33 {
            excessive.insert(format!("other{n}"), OwnedValue::from(true));
        }
        assert!(CallerProcess::from_credentials(excessive, 1000, pid).is_err());
    }

    #[test]
    fn credentials_decode_uses_exact_dictionary_shape_and_rejects_duplicates() {
        #[derive(zbus::zvariant::Type)]
        #[zvariant(signature = "a{sv}")]
        struct Fields(Vec<(String, OwnedValue)>);
        impl Serialize for Fields {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (key, value) in &self.0 {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
        let decode = |fields: Fields| {
            let message = zbus::Message::method_call(MANAGER_PATH, "Fixture")
                .and_then(|builder| builder.build(&fields))
                .unwrap_or_else(|error| unreachable!("{error}"));
            read_credentials(&message)
        };
        let value = || OwnedValue::from(1000_u32);
        assert_eq!(
            decode(Fields(vec![("UnixUserID".into(), value())]))
                .ok()
                .map(|values| values.len()),
            Some(1)
        );
        assert!(
            decode(Fields(vec![
                ("UnixUserID".into(), value()),
                ("UnixUserID".into(), value())
            ]))
            .is_err()
        );
        assert!(
            decode(Fields(
                (0..33).map(|n| (format!("key{n}"), value())).collect()
            ))
            .is_err()
        );
        assert!(decode(Fields(vec![("x".repeat(129), value())])).is_err());
    }

    #[test]
    fn oversized_native_reply_is_rejected_before_decoding() {
        let message = |bytes| {
            zbus::Message::method_call(MANAGER_PATH, "Fixture")
                .and_then(|builder| builder.build(&vec![0_u8; bytes]))
                .unwrap_or_else(|error| unreachable!("{error}"))
        };
        assert!(require_subject_reply(&message(MAX_SUBJECT_REPLY_BYTES - 4)).is_ok());
        assert!(require_subject_reply(&message(MAX_SUBJECT_REPLY_BYTES - 3)).is_err());
    }

    #[test]
    fn ordinary_file_descriptor_and_missing_broker_processfd_fail_closed() {
        let file = File::open("/dev/null").unwrap_or_else(|error| unreachable!("{error}"));
        let process = CallerProcess {
            fd: file.into(),
            pid: std::process::id(),
        };
        assert!(process.require_live().is_err());
        let values = HashMap::from([
            ("UnixUserID".into(), OwnedValue::from(1000_u32)),
            ("ProcessID".into(), OwnedValue::from(42_u32)),
        ]);
        assert!(CallerProcess::from_credentials(values, 1000, 42).is_err());
    }
}
