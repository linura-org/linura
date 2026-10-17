//! Narrow coverage bookkeeping, never lock or power execution authority.
use super::*;
use linura_core::SleepInvocationId;

impl NativeSessionChannel {
    pub fn fence_native_sleep_entry(
        &self,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Control)?;
        if event.boot() != lock.epoch().boot() || current_boot()? != *event.boot() {
            return Err("native sleep fence target crossed a boot".into());
        }
        let started = Instant::now();
        let identity = self.discover(lock.epoch().uid(), started)?;
        if identity.invocation != *lock.security_owner_invocation() {
            return Err("native sleep fence owner was replaced".into());
        }
        let event_resource = event.resource_id().map_err(|e| e.to_string())?;
        let lock_resource = lock.resource_id().map_err(|e| e.to_string())?;
        let (fenced,): (bool,) = self
            .call(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                "FenceSleepEntry",
                &(event_resource.as_str(), lock_resource.as_str()),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native sleep fence reply is malformed")?;
        self.revalidate(&identity, started)?;
        if current_boot()? != *event.boot() {
            return Err("native sleep fence acknowledgement crossed a boot".into());
        }
        Ok(fenced)
    }
}
