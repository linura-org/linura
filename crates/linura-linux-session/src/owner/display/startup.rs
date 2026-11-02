//! Authenticate a protected owner's startup transfer against independent
//! supervisor/logind evidence. This admits no display write or restoration.
use super::*;
use linura_core::{CompositorInvocationId, DisplayTopologyId, SessionEpoch};
use linura_provider_sdk::ComponentDigest;
use rustix::event::{PollFd, PollFlags, Timespec};
use std::os::fd::OwnedFd;
use zbus::zvariant::OwnedObjectPath;

fn unavailable() -> String {
    "native display startup identity unavailable; ordinary presentation remains fenced".into()
}

/// Startup correlation from the supervised native owner, never permission.
#[derive(Debug)]
pub struct NativeDisplayStartupRequest {
    lock: SessionLockId,
    native_pid: u32,
    seat: String,
    compositor: CompositorInvocationId,
    integration: ComponentDigest,
    binary: ComponentDigest,
}
impl NativeDisplayStartupRequest {
    pub fn new(
        lock: SessionLockId,
        native_pid: u32,
        seat: String,
        compositor: &str,
        integration: ComponentDigest,
        binary: ComponentDigest,
    ) -> Result<Self, String> {
        if native_pid == 0
            || native_pid > i32::MAX as u32
            || seat.is_empty()
            || seat.len() > 64
            || matches!(seat.as_str(), "self" | "auto" | "current")
            || !seat
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
            || integration == ComponentDigest::from_bytes([0; 32])
            || binary == ComponentDigest::from_bytes([0; 32])
        {
            return Err(unavailable());
        }
        Ok(Self {
            lock,
            native_pid,
            seat,
            compositor: CompositorInvocationId::new(compositor).map_err(|_| unavailable())?,
            integration,
            binary,
        })
    }
}

/// Comparison identity retained by independent display protection. The native
/// process descriptor cannot be reconstructed from a checkpoint or sender text.
#[derive(Debug)]
pub struct NativeDisplayStartupPeer {
    epoch: SessionEpoch,
    seat: String,
    compositor: CompositorInvocationId,
    integration: ComponentDigest,
    binary: ComponentDigest,
    pid: u32,
    start_ticks: u64,
    process: OwnedFd,
}
impl NativeDisplayStartupPeer {
    pub fn same_login(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.seat == other.seat
    }
    pub fn reuses_compositor(&self, other: &Self) -> bool {
        self.epoch.boot() == other.epoch.boot() && self.compositor == other.compositor
    }
    pub fn same_invocation(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && self.seat == other.seat
            && self.compositor == other.compositor
            && self.integration == other.integration
            && self.binary == other.binary
            && self.pid == other.pid
            && self.start_ticks == other.start_ticks
    }
    pub fn matches_preimage(
        &self,
        topology: &DisplayTopologyId,
        integration: &ComponentDigest,
    ) -> bool {
        self.epoch == *topology.session()
            && self.seat == topology.seat()
            && self.compositor == *topology.compositor()
            && &self.integration == integration
    }
    /// Unknown poll results are live for exclusion purposes: uncertainty cannot
    /// authorize overlapping native invocations in one login. Independent
    /// logind-active logins retain their own bound leases across VT switching.
    pub fn definitely_exited(&self) -> bool {
        let mut event = [PollFd::new(&self.process, PollFlags::IN)];
        rustix::event::poll(
            &mut event,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .is_ok_and(|count| {
            count == 1
                && event[0].revents().contains(PollFlags::IN)
                && !event[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::NVAL)
        })
    }
    pub fn live(&self) -> Result<(), String> {
        let mut event = [PollFd::new(&self.process, PollFlags::IN)];
        if rustix::event::poll(
            &mut event,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| unavailable())?
            != 0
            || !event[0].revents().is_empty()
            || super::super::process_start(self.pid)? != self.start_ticks
            || current_boot()? != *self.epoch.boot()
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl NativeSessionChannel {
    /// Only the immutable, root-supervised protected owner can transfer a
    /// startup scope. It independently inspected the actual Wayland peer and
    /// installed native image. UID alone and caller-provided process IDs are
    /// insufficient; logind independently binds the original login and seat.
    pub fn admit_display_startup(
        &self,
        sender: &str,
        request: &NativeDisplayStartupRequest,
    ) -> Result<NativeDisplayStartupPeer, String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        let started = Instant::now();
        let NativeDisplayStartupRequest {
            lock,
            native_pid,
            seat,
            compositor,
            integration,
            binary,
        } = request;
        let native_pid = *native_pid;
        if !super::super::unique_name(sender) || current_boot()? != *lock.epoch().boot() {
            return Err(unavailable());
        }
        let caller = self.connection_credentials(sender, started)?;
        let owner = self.supervised_owner(lock.epoch().uid(), started)?;
        if caller != (lock.epoch().uid(), owner.0) || owner.1 != *lock.security_owner_invocation() {
            return Err(unavailable());
        }
        let process = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(native_pid as i32).ok_or_else(unavailable)?,
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(|_| unavailable())?;
        let start_ticks = super::super::process_start(native_pid)?;
        let logind: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| unavailable())?;
        if self.connection_credentials(&logind, started)?.0 != 0 {
            return Err(unavailable());
        }
        let path: OwnedObjectPath = self
            .call(
                &logind,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(lock.epoch().session_id(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| unavailable())?;
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err(unavailable());
        }
        let facts = || {
            self.fixed_properties(
                &logind,
                path.as_str(),
                "org.freedesktop.login1.Session",
                &[
                    "User",
                    "Leader",
                    "Id",
                    "TimestampMonotonic",
                    "Type",
                    "Class",
                    "State",
                    "Active",
                    "Remote",
                    "Seat",
                ],
                started,
            )
        };
        let check = |properties: &super::super::Properties| -> Result<(), String> {
            if super::super::authentication_leader(lock, properties)? != native_pid {
                return Err(unavailable());
            }
            let value = properties
                .get("Seat")
                .ok_or_else(unavailable)?
                .try_clone()
                .map_err(|_| unavailable())?;
            let (actual, _): (String, OwnedObjectPath) = zbus::zvariant::Value::from(value)
                .try_into()
                .map_err(|_| unavailable())?;
            if &actual != seat {
                return Err(unavailable());
            }
            Ok(())
        };
        check(&facts()?)?;
        let peer = NativeDisplayStartupPeer {
            epoch: lock.epoch().clone(),
            seat: seat.clone(),
            compositor: compositor.clone(),
            integration: *integration,
            binary: *binary,
            pid: native_pid,
            start_ticks,
            process,
        };
        peer.live()?;
        check(&facts()?)?;
        let fresh_logind: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| unavailable())?;
        if fresh_logind != logind
            || self.connection_credentials(sender, started)? != caller
            || self.supervised_owner(lock.epoch().uid(), started)? != owner
        {
            return Err(unavailable());
        }
        peer.live()?;
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        pid: u32,
        seat: &str,
        compositor: &str,
        integration: u8,
        binary: u8,
    ) -> Result<NativeDisplayStartupRequest, String> {
        let lock = SessionLockId::from_resource(&linura_core::ResourceId::new(
            "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1"
        ).unwrap_or_else(|e| unreachable!("{e}"))).unwrap_or_else(|e| unreachable!("{e}"));
        NativeDisplayStartupRequest::new(
            lock,
            pid,
            seat.into(),
            compositor,
            ComponentDigest::from_bytes([integration; 32]),
            ComponentDigest::from_bytes([binary; 32]),
        )
    }

    #[test]
    fn startup_correlation_is_bounded_and_has_no_identity_aliases_or_zero_builds() {
        let compositor = "33333333-3333-4333-8333-333333333333";
        assert!(request(51, "seat0", compositor, 1, 2).is_ok());
        for pid in [0, i32::MAX as u32 + 1, u32::MAX] {
            assert!(request(pid, "seat0", compositor, 1, 2).is_err());
        }
        for seat in [
            "",
            "self",
            "auto",
            "current",
            "seat:0",
            "seat/0",
            "seat\0",
            &"s".repeat(65),
        ] {
            assert!(request(51, seat, compositor, 1, 2).is_err());
        }
        for compositor in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "33333333-3333-4333-8333-33333333333A",
        ] {
            assert!(request(51, "seat0", compositor, 1, 2).is_err());
        }
        assert!(request(51, "seat0", compositor, 0, 2).is_err());
        assert!(request(51, "seat0", compositor, 1, 0).is_err());
    }

    #[test]
    fn actual_native_pidfd_distinguishes_live_dead_and_reaped_invocations() {
        // One fixed unprivileged fixture process; no shell, caller program or
        // effect path exists in the production startup mechanism.
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let pid = child.id();
        let process = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).unwrap_or_else(|| unreachable!()),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let epoch = SessionEpoch::new(
            current_boot().unwrap_or_else(|e| unreachable!("{e}")),
            1000,
            "c2",
            42,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let peer = NativeDisplayStartupPeer {
            epoch,
            seat: "seat0".into(),
            compositor: CompositorInvocationId::new("33333333-3333-4333-8333-333333333333")
                .unwrap_or_else(|e| unreachable!("{e}")),
            integration: ComponentDigest::from_bytes([1; 32]),
            binary: ComponentDigest::from_bytes([2; 32]),
            pid,
            start_ticks: super::super::super::process_start(pid)
                .unwrap_or_else(|e| unreachable!("{e}")),
            process,
        };
        assert!(peer.live().is_ok());
        assert!(!peer.definitely_exited());
        assert!(peer.same_invocation(&peer));
        let topology =
            DisplayTopologyId::new(peer.epoch.clone(), "seat0", peer.compositor.clone(), 7)
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(peer.matches_preimage(&topology, &peer.integration));
        assert!(!peer.matches_preimage(&topology, &peer.binary));
        let mut other = NativeDisplayStartupPeer {
            epoch: peer.epoch.clone(),
            seat: peer.seat.clone(),
            compositor: peer.compositor.clone(),
            integration: peer.integration,
            binary: peer.binary,
            pid: peer.pid,
            start_ticks: peer.start_ticks,
            process: peer
                .process
                .try_clone()
                .unwrap_or_else(|e| unreachable!("{e}")),
        };
        assert!(peer.same_login(&other) && peer.reuses_compositor(&other));
        other.binary = ComponentDigest::from_bytes([3; 32]);
        assert!(!peer.same_invocation(&other) && peer.reuses_compositor(&other));
        other.epoch = SessionEpoch::new(peer.epoch.boot().clone(), 1001, "c3", 43)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(!peer.same_login(&other)); // Independent logins are not an overlap.
        assert!(peer.reuses_compositor(&other)); // UUID reuse still fails closed.
        assert!(!other.matches_preimage(&topology, &peer.integration));
        other.compositor = CompositorInvocationId::new("44444444-4444-4444-8444-444444444444")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(!peer.reuses_compositor(&other));
        child.kill().unwrap_or_else(|e| unreachable!("{e}"));
        child.wait().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(peer.definitely_exited()); // Reaped pidfd reports IN | HUP.
        assert!(peer.live().is_err());
    }
}
