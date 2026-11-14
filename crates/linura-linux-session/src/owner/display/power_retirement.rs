//! One separately prepared native-power effect on the original completion
//! lifetime. Every transport identity and both producer clocks remain bound;
//! an acknowledgement proves neither a physical postcondition nor completion.
use super::*;
use crate::{NativeDisplayCompletionPreparation, NativeDisplayPowerRetirementPreparation};
use linura_observation::{DisplayNativeCurrentFacts, DisplayOriginalCompletionFacts};
use linura_provider_sdk::ComponentDigest;

fn unavailable() -> String {
    "original native power retirement unavailable; no replay".into()
}

impl NativeSessionChannel {
    pub fn retire_original_display_native_power(
        &self,
        root_facts: &DisplayOriginalCompletionFacts,
        frames: &DisplayNativeCurrentFacts,
        preparation: ComponentDigest,
        checkpoint: ComponentDigest,
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
        let owner = self.discover(scope.replacement().session().uid(), started)?;
        let read = |method: &str, limit: usize| -> Result<(Vec<u8>, u32), String> {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                method,
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayu"
                || reply.body().len() > limit + 32
            {
                return Err(unavailable());
            }
            reply.body().deserialize().map_err(|_| unavailable())
        };
        let (parent, phase) = read(
            "ReadCompletion",
            crate::MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION,
        )?;
        let parent = NativeDisplayCompletionPreparation::decode(&parent)?;
        if phase != 2
            || parent.frames() != root_facts.first()
            || parent.parent().terminal().material() != root_facts.lineage().material
            || ComponentDigest::from_bytes(Sha256::digest(parent.canonical_bytes()).into()).to_hex()
                != root_facts.lineage().record
            || parent.preparation_digest().to_hex() != root_facts.lineage().preparation
            || parent.verification_digest().to_hex() != root_facts.lineage().verification
        {
            return Err(unavailable());
        }
        let record = NativeDisplayPowerRetirementPreparation::new(
            &parent,
            preparation,
            checkpoint,
            frames,
            expires_at_unix_ms,
        )?;
        let sample = self.observe_native_display_current(scope, 1)?;
        let fresh = DisplayNativeCurrentFacts::from_envelope(&sample, scope, unix_ms()?)
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
        // No retry after this reservation, including an absent reply.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReservePowerRetirement",
            &(&bytes,),
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
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        let bound = parent.parent().terminal().binding();
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "RetireOriginalDisplayPower",
            &(
                (
                    root_facts.lineage().material.as_str(),
                    bound.transaction_id.as_str(),
                    bound.effect_digest.to_hex(),
                    bound.dispatch_digest.to_hex(),
                    expires_at_unix_ms,
                ),
                ComponentDigest::from_bytes(Sha256::digest(&bytes).into()).to_hex(),
                &bytes,
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "u"
            || reply
                .body()
                .deserialize::<u32>()
                .map_err(|_| unavailable())?
                != 9
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        let (retained, phase) = read(
            "ReadPowerRetirement",
            crate::MAX_NATIVE_DISPLAY_POWER_RETIREMENT,
        )?;
        if phase != 2
            || retained != bytes
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        current()?;
        Ok(()) // Grant ACK only. Control independently observes the actual effect.
    }
}
