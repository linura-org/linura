//! A bounded cancellation/readiness probe, never a new effect or authority.
use super::super::{NativeSessionChannel, NativeSessionRole, boot_ms};
use linura_core::SessionLockId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug)]
pub struct NativeDisplaySafetyRequest {
    lock: SessionLockId,
    started: u64,
    last: AtomicU64,
}
impl NativeDisplaySafetyRequest {
    pub fn new(lock: SessionLockId) -> Result<Self, String> {
        Self::at(lock, boot_ms()?)
    }
    fn at(lock: SessionLockId, started: u64) -> Result<Self, String> {
        if started == 0 || started > u64::MAX - 2_000 {
            return Err("native display safety clock is unsupported".into());
        }
        Ok(Self {
            lock,
            started,
            last: AtomicU64::new(started),
        })
    }
    pub fn remaining(&self) -> Result<Duration, String> {
        self.remaining_at(boot_ms()?)
    }
    fn remaining_at(&self, now: u64) -> Result<Duration, String> {
        if now < self.last.fetch_max(now, Ordering::SeqCst) {
            self.last.store(u64::MAX, Ordering::SeqCst);
            return Err("native display safety clock rolled back".into());
        }
        now.checked_sub(self.started)
            .and_then(|elapsed| 2_000_u64.checked_sub(elapsed))
            .filter(|left| *left > 0)
            .map(Duration::from_millis)
            .ok_or_else(|| "native display restoration readiness expired".into())
    }
}
impl NativeSessionChannel {
    pub fn retire_display_for_security(
        &self,
        request: &NativeDisplaySafetyRequest,
    ) -> Result<bool, String> {
        request.remaining()?;
        let ready = self.lock_call(
            NativeSessionRole::Control,
            &request.lock,
            "RetireDisplayForSecurity",
            None,
        )?;
        request.remaining()?;
        Ok(ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock() -> SessionLockId {
        let resource = linura_core::ResourceId::new("session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1").unwrap_or_else(|e| unreachable!("{e}"));
        SessionLockId::from_resource(&resource).unwrap_or_else(|e| unreachable!("{e}"))
    }
    #[test]
    fn suspend_expiry_and_rollback_cannot_renew_readiness() {
        let request =
            NativeDisplaySafetyRequest::at(lock(), 100).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(request.remaining_at(101), Ok(Duration::from_millis(1_999)));
        assert!(request.remaining_at(2_100).is_err());
        assert!(request.remaining_at(101).is_err());
        assert!(request.remaining_at(2_101).is_err());
        let request =
            NativeDisplaySafetyRequest::at(lock(), 100).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(request.remaining_at(110).is_ok());
        assert!(request.remaining_at(109).is_err());
        assert!(request.remaining_at(111).is_err());
        assert!(NativeDisplaySafetyRequest::at(lock(), 0).is_err());
        assert!(NativeDisplaySafetyRequest::at(lock(), u64::MAX - 1).is_err());
    }
}
