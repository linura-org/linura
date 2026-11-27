//! Ordinary live Root/native grant after Control's signed current commit.
//! Transport ACKs remain separate from independent physical qualification.
use super::*;
use crate::{NativeDisplayOrdinaryCurrentPreparation, NativeDisplayOrdinaryRootPreparation};
use linura_observation::{DisplayOrdinaryCurrentFacts, DisplayOrdinaryRootRetirementFacts};
use linura_provider_sdk::ComponentDigest;
fn unavailable() -> String {
    "ordinary committed-current grant unavailable; no replay".into()
}
impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn commit_ordinary_display_current(
        &self,
        root_facts: &DisplayOrdinaryRootRetirementFacts,
        frames: &DisplayOrdinaryCurrentFacts,
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
        if boot != *scope.topology().session().boot() {
            return Err(unavailable());
        }
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let owner = self.discover(scope.topology().session().uid(), started)?;
        let read_root = || {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadOrdinaryRootPower",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayayayb"
                || reply.body().len()
                    > crate::MAX_NATIVE_DISPLAY_ORDINARY_ROOT
                        + crate::MAX_NATIVE_DISPLAY_ORDINARY_CURRENT
                        + 384 * 1024
                        + 96
            {
                return Err(unavailable());
            }
            reply
                .body()
                .deserialize::<(Vec<u8>, Vec<u8>, Vec<u8>, bool)>()
                .map_err(|_| unavailable())
        };
        let (bytes, preimage, grant, retired) = read_root()?;
        let parent = NativeDisplayOrdinaryRootPreparation::decode(&bytes)?;
        if !retired
            || !grant.is_empty()
            || ComponentDigest::from_bytes(Sha256::digest(&bytes).into()).to_hex()
                != root_facts.lineage().record
            || parent.preparation_digest().to_hex() != root_facts.lineage().preparation
            || parent.verification_digest().to_hex() != root_facts.lineage().verification
            || NativeDisplayRecoveryCheckpoint::ordinary_original_facts(&preimage, scope)?
                .comparison()
                != root_facts.original()
        {
            return Err(unavailable());
        }
        let record = NativeDisplayOrdinaryCurrentPreparation::new(
            &parent,
            preparation,
            committed_record,
            generation,
            version,
            binding,
            frames,
            expiry,
        )?;
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
        let body = record.canonical_bytes();
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveOrdinaryCurrentCommit",
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
        let bound = parent.parent().parent().parent().binding();
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "CommitOrdinaryDisplayCurrent",
            &(
                (
                    root_facts.completion().lineage().material.as_str(),
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
