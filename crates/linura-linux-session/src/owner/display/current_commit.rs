//! Original live Root/native grant after Control's signed current commit.
//! Transport ACKs remain separate from independent physical qualification.
use super::*;
use crate::{NativeDisplayCurrentCommitPreparation, NativeDisplayRootRetirementPreparation};
use linura_observation::{DisplayNativeCurrentFacts, DisplayOriginalRootRetirementFacts};
use linura_provider_sdk::ComponentDigest;
fn unavailable() -> String {
    "original committed-current grant unavailable; no replay".into()
}
impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn commit_original_display_current(
        &self,
        root_facts: &DisplayOriginalRootRetirementFacts,
        frames: &DisplayNativeCurrentFacts,
        preparation: ComponentDigest,
        committed_record: ComponentDigest,
        generation: u64,
        version: u64,
        binding: ComponentDigest,
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
        if root_facts.current_grant().is_some() || frames.current_commit_digest().is_some() {
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
        let parent = NativeDisplayRootRetirementPreparation::decode(&bytes)?;
        if !retired
            || !grant.is_empty()
            || ComponentDigest::from_bytes(Sha256::digest(&bytes).into()).to_hex()
                != root_facts.lineage().record
            || parent.preparation_digest().to_hex() != root_facts.lineage().preparation
            || parent.verification_digest().to_hex() != root_facts.lineage().verification
            || NativeDisplayRecoveryCheckpoint::original_protection_facts(&preimage, scope)?
                != *root_facts.original_comparison()
        {
            return Err(unavailable());
        }
        let record = NativeDisplayCurrentCommitPreparation::new(
            &parent,
            preparation,
            committed_record,
            generation,
            version,
            binding,
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
            "ReserveCurrentCommit",
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
        let bound = parent.parent().parent().parent().terminal().binding();
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "CommitOriginalDisplayCurrent",
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
                != 10
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        let (retained, _, spent, closed) = read_root()?;
        if retained != bytes || !closed || spent != body {
            return Err(unavailable());
        }
        Ok(()) // Permission ACK; Control separately observes native qualified lifetime.
    }
}
