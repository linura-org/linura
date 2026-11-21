//! Original live Root/native final retirement after independent qualification.
//! Transport ACKs remain separate from independent physical qualification.
use super::*;
use crate::{
    NativeDisplayCurrentCommitPreparation, NativeDisplayFinalRetirementPreparation,
    NativeDisplayReleasedCurrentRecord, NativeDisplayRootRetirementPreparation,
};
use linura_core::DisplayRecoveryScope;
use linura_observation::{DisplayNativeCurrentFacts, DisplayOriginalRootRetirementFacts};
use linura_provider_sdk::ComponentDigest;
fn unavailable() -> String {
    "original final-retirement grant unavailable; no replay".into()
}
impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn retire_original_display_current(
        &self,
        root_facts: &DisplayOriginalRootRetirementFacts,
        frames: &DisplayNativeCurrentFacts,
        preparation: ComponentDigest,
        qualified_record: ComponentDigest,
        expiry: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let scope = frames.scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let window = frames.window();
        let current = || {
            let wall = unix_ms()?;
            let boot = boot_ms()?;
            if wall < window.observed_unix_ms
                || wall >= expiry
                || wall >= window.deadline_unix_ms
                || boot < window.observed_boot_ms
                || boot >= window.deadline_boot_ms
            {
                return Err(unavailable());
            }
            Ok(())
        };
        current()?;
        if root_facts.current_grant().is_none()
            || frames.current_commit_digest().is_none()
            || frames.final_retirement_digest().is_some()
        {
            return Err(unavailable());
        }
        let started = Instant::now();
        let boot = current_boot()?;
        if boot != *scope.replacement().session().boot() {
            return Err(unavailable());
        }
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let owner = self.discover(scope.replacement().session().uid(), started)?;
        let read_root = || {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadRootPower",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayayayb"
                || reply.body().len()
                    > crate::MAX_NATIVE_DISPLAY_ROOT_RETIREMENT
                        + crate::MAX_NATIVE_DISPLAY_CURRENT_COMMIT
                        + 384 * 1024
                        + 160
            {
                return Err(unavailable());
            }
            reply
                .body()
                .deserialize::<(Vec<u8>, Vec<u8>, Vec<u8>, bool)>()
                .map_err(|_| unavailable())
        };
        let (bytes, preimage, grant, retired) = read_root()?;
        let root_parent = NativeDisplayRootRetirementPreparation::decode(&bytes)?;
        let parent = NativeDisplayCurrentCommitPreparation::decode(&grant)?;
        let lineage = root_facts.current_grant().ok_or_else(unavailable)?;
        if !retired
            || parent.parent().canonical_bytes() != bytes
            || parent.record_digest().to_hex() != lineage.record
            || parent.preparation_digest().to_hex() != lineage.preparation
            || parent.committed_record_digest().to_hex() != lineage.committed_record
            || frames.current_commit_digest() != Some(lineage.record.as_str())
            || ComponentDigest::from_bytes(Sha256::digest(&bytes).into()).to_hex()
                != root_facts.lineage().record
            || root_parent.preparation_digest().to_hex() != root_facts.lineage().preparation
            || root_parent.verification_digest().to_hex() != root_facts.lineage().verification
            || NativeDisplayRecoveryCheckpoint::original_protection_facts(&preimage, scope)?
                != *root_facts.original_comparison()
        {
            return Err(unavailable());
        }
        let record = NativeDisplayFinalRetirementPreparation::new(
            &parent,
            preparation,
            qualified_record,
            frames,
            expiry,
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
        let body = record.canonical_bytes();
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveFinalRetirement",
            &(&body,),
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
        let bound = parent
            .parent()
            .parent()
            .parent()
            .parent()
            .terminal()
            .binding();
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "RetireOriginalDisplayCurrent",
            &(
                (
                    root_facts
                        .completion_comparison()
                        .lineage()
                        .material
                        .as_str(),
                    bound.transaction_id.as_str(),
                    bound.effect_digest.to_hex(),
                    bound.dispatch_digest.to_hex(),
                    expiry,
                ),
                ComponentDigest::from_bytes(Sha256::digest(&body).into()).to_hex(),
                &body,
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
                != 11
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadFinalRetirement",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayuay"
            || reply.body().len() > 2 * crate::MAX_NATIVE_DISPLAY_FINAL_RETIREMENT + 1024
        {
            return Err(unavailable());
        }
        let (retained, phase, completed): (Vec<u8>, u32, Vec<u8>) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        if retained != body || phase != 2 || !completed.is_empty() {
            return Err(unavailable());
        }
        Ok(()) // Permission ACK; Control independently observes final native retirement.
    }

    /// Metadata completion only: this never recreates or invokes native authority.
    /// The caller supplies the immutable first post-effect proof and its clocks.
    pub fn complete_original_display_released_current(
        &self,
        scope: &DisplayRecoveryScope,
        final_record: ComponentDigest,
        verification: ComponentDigest,
        window: linura_observation::DisplayNativeHandoffWindow,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let boot = current_boot()?;
        if boot != *scope.replacement().session().boot() {
            return Err(unavailable());
        }
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let read = || {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadFinalRetirement",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayuay"
                || reply.body().len() > 2 * crate::MAX_NATIVE_DISPLAY_FINAL_RETIREMENT + 1024
            {
                return Err(unavailable());
            }
            reply
                .body()
                .deserialize::<(Vec<u8>, u32, Vec<u8>)>()
                .map_err(|_| unavailable())
        };
        let (bytes, phase, completed) = read()?;
        let parent = NativeDisplayFinalRetirementPreparation::decode(&bytes)?;
        if parent.frames().scope() != scope
            || ComponentDigest::from_bytes(Sha256::digest(&bytes).into()) != final_record
            || !matches!(phase, 2 | 3)
        {
            return Err(unavailable());
        }
        let record = NativeDisplayReleasedCurrentRecord::new(&parent, verification, window)?;
        let body = record.canonical_bytes();
        if phase == 2 {
            if !completed.is_empty() {
                return Err(unavailable());
            }
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "CompleteReleasedCurrent",
                &(&body,),
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
        } else if completed != body {
            return Err(unavailable());
        }
        let (after, phase, completed) = read()?;
        if after != bytes
            || phase != 3
            || completed != body
            || current_boot()? != boot
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
