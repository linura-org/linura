//! One ordinary Root power close. No retry, native commit, final retirement or
//! cleanup is reachable through this narrow transport mechanism.
use super::*;
use crate::{NativeDisplayOrdinaryPowerPreparation, NativeDisplayOrdinaryRootPreparation};
use linura_observation::{DisplayOrdinaryCurrentFacts, DisplayOrdinaryPowerRetirementFacts};
use linura_provider_sdk::ComponentDigest;

fn unavailable() -> String {
    "ordinary Root power retirement unavailable; no replay".into()
}
impl NativeSessionChannel {
    pub fn retire_ordinary_display_root_power(
        &self,
        power: &DisplayOrdinaryPowerRetirementFacts,
        frames: &DisplayOrdinaryCurrentFacts,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        expiry: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let scope = frames.scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let started = Instant::now();
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let boot = current_boot()?;
        let owner = self.discover(scope.topology().session().uid(), started)?;
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadOrdinaryPowerRetirement",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|s| s.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_ORDINARY_POWER + 32
        {
            return Err(unavailable());
        }
        let (bytes, phase): (Vec<u8>, u32) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let parent = NativeDisplayOrdinaryPowerPreparation::decode(&bytes)?;
        if phase != 2
            || !power.grant_spent()
            || power.scope() != scope
            || parent.frames().scope() != scope
            || parent.record_digest().to_hex() != power.record_digest()
            || parent.parent().record_digest().to_hex() != power.completion_digest()
            || parent.preparation_digest().to_hex() != power.preparation_digest()
            || parent.checkpoint_digest().to_hex() != power.checkpoint_digest()
        {
            return Err(unavailable());
        }
        let record = NativeDisplayOrdinaryRootPreparation::new(
            &parent,
            preparation,
            verification,
            frames,
            expiry,
        )?;
        let current = || {
            let w = frames.window();
            let (wall, boot) = (unix_ms()?, boot_ms()?);
            if wall < w.observed_unix_ms
                || wall >= expiry
                || boot < w.observed_boot_ms
                || boot >= w.deadline_boot_ms
            {
                return Err(unavailable());
            }
            Ok(())
        };
        let sample = self.observe_ordinary_display_current(scope, 1)?;
        let fresh = DisplayOrdinaryCurrentFacts::from_envelope(&sample, scope, unix_ms()?)
            .map_err(|_| unavailable())?;
        if !fresh.reconciles(frames) {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        let bytes = record.canonical_bytes();
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "RetireOrdinaryRootPower",
            &(&bytes,),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|s| s.as_str() != root.sender)
            || reply.body().signature().to_string() != "b"
            || !reply
                .body()
                .deserialize::<bool>()
                .map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        Ok(()) // Close ACK, never physical qualification.
    }
}
