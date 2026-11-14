//! Fixed protection mechanism inside an already admitted prepared display
//! operation. This cannot request power, bypass an inhibitor or authorize an
//! effect. Keep its ORIGINAL logind FIFO outside compositor memory; never
//! reacquire it after service replacement or infer terminal recovery from it.
use super::*;
use rustix::event::{PollFd, PollFlags, Timespec};
use std::os::fd::OwnedFd;

const MANAGER: &str = "/org/freedesktop/login1";
const INTERFACE: &str = "org.freedesktop.login1.Manager";

fn unavailable() -> String {
    "independent display recovery power fence unavailable; no continuation".into()
}

#[derive(Debug)]
struct Lease {
    fd: OwnedFd,
    valid: bool,
}
impl Lease {
    fn verify(&mut self) -> Result<(), String> {
        let result = (|| {
            if !self.valid
                || rustix::fs::FileType::from_raw_mode(
                    rustix::fs::fstat(&self.fd)
                        .map_err(|_| unavailable())?
                        .st_mode,
                ) != rustix::fs::FileType::Fifo
                || !rustix::io::fcntl_getfd(&self.fd)
                    .map_err(|_| unavailable())?
                    .contains(rustix::io::FdFlags::CLOEXEC)
            {
                return Err(unavailable());
            }
            let mut poll = [PollFd::new(&self.fd, PollFlags::IN)];
            if rustix::event::poll(
                &mut poll,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )
            .map_err(|_| unavailable())?
                != 0
                || !poll[0].revents().is_empty()
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }
}

/// An opaque, non-cloneable original logind lifetime. Independent protection retains it
/// across executor/compositor loss; only separately qualified terminal handling may
/// retire it. No pipe or bus primitive leaves this concrete adapter.
pub struct NativeDisplayPowerFence {
    owner: String,
    boot: linura_core::BootId,
    lease: Lease,
    dispatch: linura_provider_sdk::ComponentDigest,
}
/// Opaque evidence of closing the one original descriptor. It is not proof
/// that logind has processed that close; fresh absence is checked separately.
pub struct NativeDisplayRetiredPowerFence {
    owner: String,
    boot: linura_core::BootId,
    dispatch: linura_provider_sdk::ComponentDigest,
}
impl std::fmt::Debug for NativeDisplayRetiredPowerFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDisplayRetiredPowerFence")
            .finish_non_exhaustive()
    }
}
impl NativeDisplayPowerFence {
    /// Consume only after the original Root's separately authorized, durable
    /// before-effect preparation and fresh revalidation. No descriptor escapes.
    /// An error after this close is indeterminate; this lease cannot be reopened.
    pub fn retire(self) -> NativeDisplayRetiredPowerFence {
        let Self {
            owner,
            boot,
            dispatch,
            lease,
        } = self;
        drop(lease);
        NativeDisplayRetiredPowerFence {
            owner,
            boot,
            dispatch,
        }
    }
}
fn inhibitor_reason(dispatch: &linura_provider_sdk::ComponentDigest) -> String {
    format!("Display recovery checkpoint {}", dispatch.to_hex())
}
impl std::fmt::Debug for NativeDisplayPowerFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDisplayPowerFence")
            .finish_non_exhaustive()
    }
}
impl NativeSessionChannel {
    fn display_power_conditions(&self, owner: &str, started: Instant) -> Result<(), String> {
        let properties = self.fixed_properties(
            owner,
            MANAGER,
            INTERFACE,
            &["PreparingForSleep", "PreparingForShutdown"],
            started,
        )?;
        not_preparing(&properties)
    }
    /// Called only by independent protection during the fixed executor's original
    /// prepared-checkpoint callback. No caller-selected reason, scope, mode, peer or retry exists.
    pub fn retain_display_recovery_power_fence(
        &self,
        dispatch: linura_provider_sdk::ComponentDigest,
    ) -> Result<NativeDisplayPowerFence, String> {
        if dispatch == linura_provider_sdk::ComponentDigest::from_bytes([0; 32]) {
            return Err(unavailable());
        }
        self.require_role(NativeSessionRole::DisplayProtection)?;
        let started = Instant::now();
        let boot = current_boot()?;
        let owner = self.logind_owner(started)?;
        self.display_power_conditions(&owner, started)?;
        let reply = self.call(
            &owner,
            MANAGER,
            INTERFACE,
            "Inhibit",
            &(
                "sleep:shutdown",
                "Linura",
                inhibitor_reason(&dispatch),
                "block",
            ),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner)
            || reply.body().signature().to_string() != "h"
        {
            return Err(unavailable());
        }
        let (fd,): (zbus::zvariant::OwnedFd,) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let mut fence = NativeDisplayPowerFence {
            dispatch,
            owner,
            boot,
            lease: Lease {
                fd: fd.into(),
                valid: true,
            },
        };
        self.verify_display_power_fence_at(&mut fence, started)?;
        Ok(fence)
    }
    /// Continuity of the original retired descriptor's service and boot. This
    /// does not claim logind has processed its close; absence has its own probe.
    pub fn verify_retired_display_power_lifetime(
        &self,
        fence: &NativeDisplayRetiredPowerFence,
    ) -> Result<(), String> {
        let started = Instant::now();
        self.require_role(NativeSessionRole::DisplayProtection)?;
        if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
            return Err(unavailable());
        }
        self.display_power_conditions(&fence.owner, started)?;
        if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
            return Err(unavailable());
        }
        Ok(())
    }
    /// Read-only identity continuity after final Root/native retirement. This
    /// does not assert a power inhibitor, an absent inhibitor, or a quiet power
    /// transition. Pending retirement uses the stricter separate probes above.
    pub fn verify_released_display_power_identity(
        &self,
        fence: &NativeDisplayRetiredPowerFence,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        let started = Instant::now();
        if current_boot()? != fence.boot
            || self.logind_owner(started)? != fence.owner
            || current_boot()? != fence.boot
        {
            return Err(unavailable());
        }
        Ok(())
    }
    /// Read-only independent logind processing of the original descriptor
    /// close. Other scopes may retain their own blockers; they are not ours to
    /// release. A same-PID unrelated scope cannot substitute for this identity.
    pub fn verify_retired_display_recovery_power_fence(
        &self,
        fence: &NativeDisplayRetiredPowerFence,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        let started = Instant::now();
        if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
            return Err(unavailable());
        }
        self.display_power_conditions(&fence.owner, started)?;
        self.verify_retired_power_absence_at(fence, started)?;
        self.display_power_conditions(&fence.owner, started)
    }
    /// Fresh scope-specific absence after final completion; no pending
    /// transition protection is claimed or reacquired.
    pub fn verify_released_display_power_absence(
        &self,
        fence: &NativeDisplayRetiredPowerFence,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        let started = Instant::now();
        if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
            return Err(unavailable());
        }
        self.verify_retired_power_absence_at(fence, started)
    }
    fn verify_retired_power_absence_at(
        &self,
        fence: &NativeDisplayRetiredPowerFence,
        started: Instant,
    ) -> Result<(), String> {
        let reply = self.call(
            &fence.owner,
            MANAGER,
            INTERFACE,
            "ListInhibitors",
            &(),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != fence.owner)
            || reply.body().signature().to_string() != "a(ssssuu)"
            || reply.body().len() > 32 * 4096
        {
            return Err(unavailable());
        }
        let rows: Vec<(String, String, String, String, u32, u32)> =
            reply.body().deserialize().map_err(|_| unavailable())?;
        retired_inhibitor_absent(&rows, &fence.dispatch)?;
        if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
            return Err(unavailable());
        }
        Ok(())
    }
    fn verify_display_power_fence_at(
        &self,
        fence: &mut NativeDisplayPowerFence,
        started: Instant,
    ) -> Result<(), String> {
        let result = (|| {
            fence.lease.verify()?;
            self.require_role(NativeSessionRole::DisplayProtection)?;
            if current_boot()? != fence.boot || self.logind_owner(started)? != fence.owner {
                return Err(unavailable());
            }
            self.display_power_conditions(&fence.owner, started)?;
            if self.logind_owner(started)? != fence.owner || current_boot()? != fence.boot {
                return Err(unavailable());
            }
            fence.lease.verify()
        })();
        if result.is_err() {
            fence.lease.valid = false;
        }
        result
    }
    /// Current bounded revalidation, not reacquisition. Any failed peer, state,
    /// budget or pipe check permanently poisons the original lifetime.
    pub fn verify_display_recovery_power_fence(
        &self,
        fence: &mut NativeDisplayPowerFence,
    ) -> Result<(), String> {
        self.verify_display_power_fence_at(fence, Instant::now())
    }
}

fn retired_inhibitor_absent(
    rows: &[(String, String, String, String, u32, u32)],
    dispatch: &linura_provider_sdk::ComponentDigest,
) -> Result<(), String> {
    if rows.len() > 32
        || rows.iter().any(|(what, who, reason, mode, _, _)| {
            [what, who, reason, mode]
                .iter()
                .any(|text| text.len() > 4096)
        })
    {
        return Err(unavailable());
    }
    let reason = inhibitor_reason(dispatch);
    // Any remaining exact scope, even with another UID/PID or malformed flags,
    // is ambiguity. Do not remove other entries or infer absence from counts.
    if rows.iter().any(|(_, _, why, _, _, _)| why == &reason) {
        return Err(unavailable());
    }
    Ok(())
}

fn not_preparing(
    properties: &std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
) -> Result<(), String> {
    if super::super::property::<bool>(properties, "PreparingForSleep")?
        || super::super::property::<bool>(properties, "PreparingForShutdown")?
    {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
