//! Single original Root close after Control's separately durable preparation.
//! Transport acknowledgements never certify completion or repeatable authority.
use super::*;
use crate::{NativeDisplayPowerRetirementPreparation, NativeDisplayRootRetirementPreparation};
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayOriginalCompletionFacts, DisplayOriginalPowerRetirementFacts,
};
use linura_provider_sdk::ComponentDigest;
fn unavailable() -> String {
    "original Root power retirement unavailable; no replay".into()
}
impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn retire_original_display_root_power(
        &self,
        completion: &DisplayOriginalCompletionFacts,
        power: &DisplayOriginalPowerRetirementFacts,
        frames: &DisplayNativeCurrentFacts,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        expires_at_unix_ms: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let scope = frames.scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let window = frames.window();
        let current = || {
            let wall = unix_ms()?;
            let boot = boot_ms()?;
            if wall < window.observed_unix_ms
                || wall >= expires_at_unix_ms
                || wall >= window.deadline_unix_ms
                || boot < window.observed_boot_ms
                || boot >= window.deadline_boot_ms
            {
                return Err(unavailable());
            }
            Ok(())
        };
        current()?;
        let started = Instant::now();
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let boot = current_boot()?;
        if boot != *scope.replacement().session().boot() || !power.grant_spent() {
            return Err(unavailable());
        }
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadPowerRetirement",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_POWER_RETIREMENT + 32
        {
            return Err(unavailable());
        }
        let (bytes, phase): (Vec<u8>, u32) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let parent = NativeDisplayPowerRetirementPreparation::decode(&bytes)?;
        let original = parent.parent();
        if phase != 2
            || ComponentDigest::from_bytes(Sha256::digest(&bytes).into()).to_hex()
                != power.record_digest()
            || ComponentDigest::from_bytes(Sha256::digest(original.canonical_bytes()).into())
                .to_hex()
                != completion.lineage().record
            || power.completion_digest() != completion.lineage().record
            || parent.preparation_digest().to_hex() != power.preparation_digest()
            || parent.checkpoint_digest().to_hex() != power.checkpoint_digest()
            || original.frames() != completion.first()
            || original.preparation_digest().to_hex() != completion.lineage().preparation
            || original.verification_digest().to_hex() != completion.lineage().verification
            || original.parent().terminal().material() != completion.lineage().material
        {
            return Err(unavailable());
        }
        let record = NativeDisplayRootRetirementPreparation::new(
            &parent,
            preparation,
            verification,
            frames,
            expires_at_unix_ms,
        )?;
        let sample = self.observe_native_display_current(scope, 1)?;
        let fresh = DisplayNativeCurrentFacts::from_envelope(&sample, scope, unix_ms()?)
            .map_err(|_| unavailable())?;
        if !fresh.reconciles(frames)
            || current_boot()? != boot
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        current()?;
        // Root reserves and reads back the complete exact ancestry before its
        // single scoped descriptor close. No retry after any ambiguous reply.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "RetireRootPower",
            &(&record.canonical_bytes(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "b"
            || !reply
                .body()
                .deserialize::<bool>()
                .map_err(|_| unavailable())?
            || current_boot()? != boot
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        current()?;
        Ok(()) // Close ACK only. Independent power/current joins are still required.
    }
}
