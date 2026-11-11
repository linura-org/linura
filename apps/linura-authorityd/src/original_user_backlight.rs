//! Inactive, fixed-purpose original-session backlight mechanism (S21-3).
//!
//! This component is not a service, grant issuer, executable route or policy
//! authority. The accepted protected-supervisor handoff does not exist yet:
//! `QualifiedBacklightAttempt` has NO public constructor. A root S17 executor,
//! arbitrary same-UID client or application cannot call this as a substitute
//! for Control. The only actual effect is the fixed logind Session.SetBrightness
//! call, on the original user's own authenticated D-Bus connection.
//!
//! A returned acknowledgement is NOT independent actual-brightness evidence.
//! Control must independently verify and reconcile its durable attempt.

use std::cell::Cell;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{BacklightResourceId, SessionEpoch};
use linura_linux_observation::backlight::candidate::{
    BacklightCandidate, observe_caller_backlight_candidate,
    observe_caller_backlight_candidate_with_budget,
};
use linura_linux_observation::backlight::verification::review_native_precondition;
use rustix::process::{geteuid, getuid};
use zbus::blocking::Connection;
use zbus::zvariant::OwnedObjectPath;
use zbus::zvariant::{DynamicType, Type};

const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const LOGIND_NAME: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const FIXED_SUBSYSTEM: &str = "backlight";
const MAX_DISPATCH_BUDGET: Duration = Duration::from_secs(2);
const NATIVE_RPC_BUDGET: Duration = Duration::from_millis(500);
const MAX_NATIVE_REPLY_BYTES: usize = 16 * 1024;

/// One original native attempt clock. BOOTTIME includes suspend; wall time
/// additionally rejects clock regression or forward expiry. Reobserving a
/// session, resolving a path or receiving a reply cannot renew this budget.
#[derive(Debug)]
struct DispatchDeadline {
    boot: Duration,
    unix: Duration,
    last: Cell<(Duration, Duration)>,
}

impl DispatchDeadline {
    fn start() -> Result<Self, OriginalUserBacklightError> {
        let (boot, unix) = Self::now()?;
        Ok(Self {
            boot,
            unix,
            last: Cell::new((boot, unix)),
        })
    }

    fn now() -> Result<(Duration, Duration), OriginalUserBacklightError> {
        let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let secs =
            u64::try_from(boot.tv_sec).map_err(|_| OriginalUserBacklightError::AttemptExpired)?;
        let nanos =
            u32::try_from(boot.tv_nsec).map_err(|_| OriginalUserBacklightError::AttemptExpired)?;
        if nanos >= 1_000_000_000 {
            return Err(OriginalUserBacklightError::AttemptExpired);
        }
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OriginalUserBacklightError::AttemptExpired)?;
        Ok((Duration::new(secs, nanos), unix))
    }

    fn remaining(&self) -> Result<Duration, OriginalUserBacklightError> {
        let (boot, unix) = Self::now()?;
        self.remaining_at(boot, unix)
    }

    fn remaining_at(
        &self,
        boot: Duration,
        unix: Duration,
    ) -> Result<Duration, OriginalUserBacklightError> {
        let last = self.last.get();
        if boot < last.0 || unix < last.1 {
            return Err(OriginalUserBacklightError::AttemptExpired);
        }
        self.last.set((boot, unix));
        let boot = boot
            .checked_sub(self.boot)
            .ok_or(OriginalUserBacklightError::AttemptExpired)?;
        let unix = unix
            .checked_sub(self.unix)
            .ok_or(OriginalUserBacklightError::AttemptExpired)?;
        MAX_DISPATCH_BUDGET
            .checked_sub(boot.max(unix))
            .filter(|left| !left.is_zero())
            .ok_or(OriginalUserBacklightError::AttemptExpired)
    }

    async fn wait<T>(
        &self,
        pending: impl Future<Output = Result<T, OriginalUserBacklightError>>,
    ) -> Result<T, OriginalUserBacklightError> {
        let start = Self::now()?;
        let timeout = self.remaining_at(start.0, start.1)?.min(NATIVE_RPC_BUDGET);
        let result = futures_lite::future::race(pending, async {
            async_io::Timer::after(timeout).await;
            Err(OriginalUserBacklightError::ProviderUnavailable)
        })
        .await;
        let end = Self::now()?;
        self.remaining_at(end.0, end.1)?;
        require_rpc_elapsed(start, end, timeout)?;
        result
    }
}

fn require_rpc_elapsed(
    start: (Duration, Duration),
    end: (Duration, Duration),
    cap: Duration,
) -> Result<(), OriginalUserBacklightError> {
    let boot = end
        .0
        .checked_sub(start.0)
        .ok_or(OriginalUserBacklightError::AttemptExpired)?;
    let unix = end
        .1
        .checked_sub(start.1)
        .ok_or(OriginalUserBacklightError::AttemptExpired)?;
    if boot.max(unix) >= cap {
        return Err(OriginalUserBacklightError::ProviderUnavailable);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalUserBacklightError {
    WrongCaller,
    UntrustedBus,
    SessionUnavailable,
    StaleSubject,
    UnqualifiedAttempt,
    UnsafeNativeValue,
    AttemptConsumed,
    AttemptExpired,
    ProviderUnavailable,
    /// A provider call may have executed before its reply was lost.
    /// Caller MUST use durable observe-only recovery; NEVER retry.
    IndeterminateDispatch,
}

/// A single verified *input* to a future original-user worker, intentionally
/// impossible for external crates to mint. The separate trusted supervisor
/// must eventually verify and issue it from the exact persisted Control
/// dispatch reservation, attested worker invocation, enrolled hardware and
/// independently calibrated floor. Until then, there is no live dispatch path.
pub struct QualifiedBacklightAttempt {
    resource: BacklightResourceId,
    original: BacklightCandidate,
    qualified_minimum: u32,
    native_value: u32,
    expires: DispatchDeadline,
}

impl Debug for QualifiedBacklightAttempt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QualifiedBacklightAttempt")
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

/// Non-cloneable worker with one native system-bus connection and one attempt
/// budget. The constructor authenticates the *current process* and its bus
/// sender, never a UI-reported PID, UID, seat or session.
pub struct OriginalUserBacklightWorker {
    connection: Connection,
    epoch: SessionEpoch,
    sender: String,
    bus_guid: String,
    pid: u32,
    used: bool,
}

impl Debug for OriginalUserBacklightWorker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalUserBacklightWorker")
            .field("epoch", &self.epoch)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

fn require_kernel_user(
    real: u32,
    effective: u32,
    expected: u32,
) -> Result<(), OriginalUserBacklightError> {
    if expected == 0
        || expected == u32::MAX
        || real == 0
        || effective == 0
        || real != effective
        || real != expected
    {
        return Err(OriginalUserBacklightError::WrongCaller);
    }
    Ok(())
}

/// Fixed native replies contain bounded scalar data and no descriptors.
fn require_native_reply(reply: &zbus::Message) -> Result<(), OriginalUserBacklightError> {
    if reply.body().len() > MAX_NATIVE_REPLY_BYTES || !reply.body().data().fds().is_empty() {
        return Err(OriginalUserBacklightError::ProviderUnavailable);
    }
    Ok(())
}

/// Provider transport failure after a dispatch attempt is never evidence
/// that the native effect did not occur. Do not translate this into a
/// pre-dispatch unavailability or a replayable rejection.
fn ambiguous_native_reply<T, E>(reply: Result<T, E>) -> Result<T, OriginalUserBacklightError> {
    reply.map_err(|_| OriginalUserBacklightError::IndeterminateDispatch)
}

impl OriginalUserBacklightWorker {
    /// Connect from an already protected, *original login-session* process.
    /// This method does not prove the supervisor's binary/IPC isolation and is
    /// not a service registration. Root, foreign UID, and a same-UID process
    /// outside the exact logind session are denied.
    pub fn connect(expected: SessionEpoch) -> Result<Self, OriginalUserBacklightError> {
        require_kernel_user(getuid().as_raw(), geteuid().as_raw(), expected.uid())?;
        let deadline = DispatchDeadline::start()?;
        let connection = linura_linux_session::connect_original_user_system_bus(expected.uid())
            .map_err(|_| OriginalUserBacklightError::UntrustedBus)?;
        let sender = connection
            .unique_name()
            .ok_or(OriginalUserBacklightError::UntrustedBus)?
            .as_str()
            .to_owned();
        let bus_guid = connection.server_guid().to_owned();
        let pid = std::process::id();
        let worker = Self {
            connection,
            epoch: expected,
            sender,
            bus_guid,
            pid,
            used: false,
        };
        worker.observe_before(&deadline)?;
        Ok(worker)
    }

    /// Read-only fresh original-caller proof pinned to this very system-bus
    /// sender. The native observer independently obtains kernel ProcessFD
    /// credentials and checks the exact logind epoch and device inventory.
    pub fn observe(&self) -> Result<BacklightCandidate, OriginalUserBacklightError> {
        require_kernel_user(getuid().as_raw(), geteuid().as_raw(), self.epoch.uid())?;
        observe_caller_backlight_candidate(&self.epoch, &self.bus_guid, &self.sender, self.pid)
            .map_err(|_| OriginalUserBacklightError::StaleSubject)
    }

    fn observe_before(
        &self,
        deadline: &DispatchDeadline,
    ) -> Result<BacklightCandidate, OriginalUserBacklightError> {
        require_kernel_user(getuid().as_raw(), geteuid().as_raw(), self.epoch.uid())?;
        let observed = observe_caller_backlight_candidate_with_budget(
            &self.epoch,
            &self.bus_guid,
            &self.sender,
            self.pid,
            deadline.remaining()?,
        )
        .map_err(|_| OriginalUserBacklightError::StaleSubject)?;
        deadline.remaining()?;
        Ok(observed)
    }

    // All parameters originate from fixed code or already attested native
    // inventory. This private transport helper is never an IPC forwarding API.
    #[allow(clippy::too_many_arguments)]
    fn native_call<T, B>(
        &self,
        deadline: &DispatchDeadline,
        destination: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> Result<T, OriginalUserBacklightError>
    where
        T: serde::de::DeserializeOwned + Type,
        B: serde::Serialize + DynamicType,
    {
        let reply = async_io::block_on(deadline.wait(async {
            self.connection
                .inner()
                .call_method(Some(destination), path, Some(interface), method, body)
                .await
                .map_err(|_| OriginalUserBacklightError::ProviderUnavailable)
        }))?;
        require_native_reply(&reply)?;
        let decoded = reply
            .body()
            .deserialize()
            .map_err(|_| OriginalUserBacklightError::ProviderUnavailable)?;
        deadline.remaining()?;
        Ok(decoded)
    }

    fn logind_session_path(
        &self,
        original: &BacklightCandidate,
        deadline: &DispatchDeadline,
    ) -> Result<OwnedObjectPath, OriginalUserBacklightError> {
        let owner: String = self.native_call(
            deadline,
            BUS_NAME,
            BUS_PATH,
            BUS_NAME,
            "GetNameOwner",
            &(LOGIND_NAME,),
        )?;
        if owner != original.session.logind_owner
            || zbus::names::UniqueName::try_from(owner.as_str()).is_err()
        {
            return Err(OriginalUserBacklightError::StaleSubject);
        }
        let owner_uid: u32 = self.native_call(
            deadline,
            BUS_NAME,
            BUS_PATH,
            BUS_NAME,
            "GetConnectionUnixUser",
            &(owner.as_str(),),
        )?;
        if owner_uid != 0 {
            return Err(OriginalUserBacklightError::StaleSubject);
        }
        let path: OwnedObjectPath = self.native_call(
            deadline,
            &owner,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetSession",
            &(self.epoch.session_id(),),
        )?;
        let by_pid: OwnedObjectPath = self.native_call(
            deadline,
            &owner,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetSessionByPID",
            &(self.pid,),
        )?;
        if path != by_pid
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
            || path.as_str().len() > 256
        {
            return Err(OriginalUserBacklightError::StaleSubject);
        }
        Ok(path)
    }

    /// Fixed native mechanism, not a public grant-issuance API.
    ///
    /// Every invocation consumes this worker's only attempt before checking
    /// mutable state; a timeout, rejection, or lost reply is never retried.
    /// A future authenticated supervisor must provide the opaque, immutable
    /// `QualifiedBacklightAttempt` only after durable reservation and physical
    /// qualification. No production component currently constructs one.
    pub fn dispatch_once(
        &mut self,
        attempt: QualifiedBacklightAttempt,
    ) -> Result<(), OriginalUserBacklightError> {
        if self.used {
            return Err(OriginalUserBacklightError::AttemptConsumed);
        }
        self.used = true;
        attempt.expires.remaining()?;
        if attempt.resource.epoch() != &self.epoch {
            return Err(OriginalUserBacklightError::UnqualifiedAttempt);
        }
        let fresh = self.observe_before(&attempt.expires)?;
        validate_attempt(
            &self.epoch,
            &attempt.resource,
            &attempt.original,
            &fresh,
            attempt.native_value,
            attempt.qualified_minimum,
        )?;
        let session_path = self.logind_session_path(&fresh, &attempt.expires)?;
        // The native probe and logind path lookup can take time. Reobserve
        // the exact original caller and hardware again before the effect:
        // expiry or an intervening owner/device/session turnover is never
        // permission to send a late request.
        let final_native = self.observe_before(&attempt.expires)?;
        validate_attempt(
            &self.epoch,
            &attempt.resource,
            &attempt.original,
            &final_native,
            attempt.native_value,
            attempt.qualified_minimum,
        )?;
        if final_native.session.logind_owner != fresh.session.logind_owner
            || final_native.kernel.identity != fresh.kernel.identity
        {
            return Err(OriginalUserBacklightError::StaleSubject);
        }
        // The final call uses the attested original-user connection and unique
        // logind owner. Any failure after this attempt is uncertainty, including
        // timeout, late reply, invalid reply and expiry observed after sending.
        attempt.expires.remaining()?;
        let acknowledged: () = ambiguous_native_reply(self.native_call(
            &attempt.expires,
            fresh.session.logind_owner.as_str(),
            session_path.as_str(),
            SESSION_INTERFACE,
            "SetBrightness",
            &(
                FIXED_SUBSYSTEM,
                fresh.kernel.identity.name.as_str(),
                attempt.native_value,
            ),
        ))?;
        Ok(acknowledged)
    }
}

fn validate_attempt(
    epoch: &SessionEpoch,
    resource: &BacklightResourceId,
    original: &BacklightCandidate,
    fresh: &BacklightCandidate,
    native_value: u32,
    qualified_minimum: u32,
) -> Result<(), OriginalUserBacklightError> {
    if resource.epoch() != epoch
        || original.session.uid != epoch.uid()
        || original.session.session_id != epoch.session_id()
        || original.session.boot_id != epoch.boot().as_str()
        || original.session.created_monotonic_us != epoch.created_monotonic_us()
        || original.session.seat_id != fresh.session.seat_id
        || original.kernel.identity.name.is_empty()
    {
        return Err(OriginalUserBacklightError::UnqualifiedAttempt);
    }
    review_native_precondition(original, fresh, native_value, qualified_minimum)
        .map_err(|_| OriginalUserBacklightError::UnsafeNativeValue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_foreign_and_effective_uid_substitutions_are_denied() {
        assert_eq!(require_kernel_user(1000, 1000, 1000), Ok(()));
        for (real, effective, expected) in [
            (0, 0, 0),
            (u32::MAX, u32::MAX, u32::MAX),
            (0, 0, 1000),
            (1000, 0, 1000),
            (1000, 1000, 0),
            (1000, 1001, 1000),
            (1001, 1001, 1000),
            (1000, 1000, 1001),
        ] {
            assert_eq!(
                require_kernel_user(real, effective, expected),
                Err(OriginalUserBacklightError::WrongCaller)
            );
        }
    }

    #[test]
    fn expiry_includes_suspend_wall_changes_and_exclusive_original_budget() {
        let deadline = DispatchDeadline {
            boot: Duration::from_secs(10),
            unix: Duration::from_secs(100),
            last: Cell::new((Duration::from_secs(10), Duration::from_secs(100))),
        };
        assert_eq!(
            deadline.remaining_at(Duration::from_secs(10), Duration::from_secs(100)),
            Ok(Duration::from_secs(2))
        );
        assert_eq!(
            deadline.remaining_at(Duration::from_millis(11_999), Duration::from_secs(100)),
            Ok(Duration::from_millis(1))
        );
        for (boot, unix) in [
            (12_000, 100_000),
            (10_000, 102_000),
            (9_999, 100_000),
            (10_000, 99_999),
        ] {
            assert_eq!(
                deadline.remaining_at(Duration::from_millis(boot), Duration::from_millis(unix)),
                Err(OriginalUserBacklightError::AttemptExpired)
            );
        }
    }

    #[test]
    fn partial_wall_regression_cannot_renew_a_previously_shortened_budget() {
        let deadline = DispatchDeadline {
            boot: Duration::from_secs(10),
            unix: Duration::from_secs(100),
            last: Cell::new((Duration::from_secs(10), Duration::from_secs(100))),
        };
        assert!(
            deadline
                .remaining_at(
                    Duration::from_millis(10_100),
                    Duration::from_millis(100_800)
                )
                .is_ok()
        );
        assert_eq!(
            deadline.remaining_at(
                Duration::from_millis(10_200),
                Duration::from_millis(100_700)
            ),
            Err(OriginalUserBacklightError::AttemptExpired)
        );
    }

    #[test]
    fn a_ready_reply_cannot_win_after_its_exclusive_rpc_cap() {
        let start = (Duration::from_secs(10), Duration::from_secs(100));
        assert_eq!(
            require_rpc_elapsed(
                start,
                (start.0 + NATIVE_RPC_BUDGET, start.1),
                NATIVE_RPC_BUDGET
            ),
            Err(OriginalUserBacklightError::ProviderUnavailable)
        );
        assert_eq!(
            require_rpc_elapsed(
                start,
                (start.0, start.1 + NATIVE_RPC_BUDGET),
                NATIVE_RPC_BUDGET
            ),
            Err(OriginalUserBacklightError::ProviderUnavailable)
        );
        assert!(
            require_rpc_elapsed(
                start,
                (start.0 + Duration::from_millis(499), start.1),
                NATIVE_RPC_BUDGET
            )
            .is_ok()
        );
    }

    #[test]
    fn expired_deadline_does_not_poll_or_send_a_native_future() {
        let (boot, unix) = DispatchDeadline::now().unwrap_or_else(|e| unreachable!("{e:?}"));
        let deadline = DispatchDeadline {
            boot,
            unix: unix.saturating_sub(MAX_DISPATCH_BUDGET),
            last: Cell::new((boot, unix.saturating_sub(MAX_DISPATCH_BUDGET))),
        };
        let polled = Cell::new(false);
        let result = async_io::block_on(deadline.wait(async {
            polled.set(true);
            Ok(())
        }));
        assert_eq!(result, Err(OriginalUserBacklightError::AttemptExpired));
        assert!(!polled.get());
    }

    #[test]
    fn a_stalled_rpc_is_bounded_and_cannot_inherit_the_sixty_second_timeout() {
        let deadline = DispatchDeadline::start().unwrap_or_else(|e| unreachable!("{e:?}"));
        let result: Result<(), _> = async_io::block_on(deadline.wait(std::future::pending()));
        assert!(matches!(
            result,
            Err(OriginalUserBacklightError::ProviderUnavailable
                | OriginalUserBacklightError::AttemptExpired)
        ));
    }

    #[test]
    fn native_replies_are_bounded_and_cannot_smuggle_descriptors() {
        let message = |bytes| {
            zbus::Message::method_call(MANAGER_PATH, "Fixture")
                .and_then(|builder| builder.build(&vec![0_u8; bytes]))
                .unwrap_or_else(|e| unreachable!("{e}"))
        };
        assert!(require_native_reply(&message(MAX_NATIVE_REPLY_BYTES - 4)).is_ok());
        assert!(require_native_reply(&message(MAX_NATIVE_REPLY_BYTES - 3)).is_err());
        let fd = std::fs::File::open("/dev/null").unwrap_or_else(|e| unreachable!("{e}"));
        let reply = zbus::Message::method_call(MANAGER_PATH, "Fixture")
            .and_then(|builder| builder.build(&zbus::zvariant::Fd::from(&fd)))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(require_native_reply(&reply).is_err());
    }

    #[test]
    fn lost_provider_reply_is_indeterminate_not_retryable_refusal() {
        assert_eq!(
            ambiguous_native_reply::<(), _>(Err("timeout")),
            Err(OriginalUserBacklightError::IndeterminateDispatch)
        );
        assert_eq!(ambiguous_native_reply::<(), &str>(Ok(())), Ok(()));
        for cause in [
            OriginalUserBacklightError::AttemptExpired,
            OriginalUserBacklightError::ProviderUnavailable,
        ] {
            assert_eq!(
                ambiguous_native_reply::<(), _>(Err(cause)),
                Err(OriginalUserBacklightError::IndeterminateDispatch)
            );
        }
    }

    #[test]
    fn no_external_bearer_or_cloneable_dispatch_credential_is_exposed() {
        // A future trusted supervisor must implement the missing issuer,
        // protected worker invocation and durable one-use IPC *in this crate*.
        // There is deliberately no `new` or `from_wire` on the grant.
        assert_eq!(FIXED_SUBSYSTEM, "backlight");
        assert_eq!(SESSION_INTERFACE, "org.freedesktop.login1.Session");
    }
}
