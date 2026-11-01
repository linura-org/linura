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

/// An opaque, non-cloneable original logind lifetime. The executor retains it
/// across compositor loss; only separately qualified terminal handling may
/// retire it. No pipe or bus primitive leaves this concrete adapter.
pub struct NativeDisplayPowerFence {
    owner: String,
    boot: linura_core::BootId,
    lease: Lease,
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
    /// Called only inside the fixed executor's original prepared-checkpoint
    /// callback. No caller-selected reason, scope, mode, peer or retry exists.
    pub fn retain_display_recovery_power_fence(&self) -> Result<NativeDisplayPowerFence, String> {
        self.require_role(NativeSessionRole::Executor)?;
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
                "Display configuration recovery",
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
    fn verify_display_power_fence_at(
        &self,
        fence: &mut NativeDisplayPowerFence,
        started: Instant,
    ) -> Result<(), String> {
        let result = (|| {
            fence.lease.verify()?;
            self.require_role(NativeSessionRole::Executor)?;
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
