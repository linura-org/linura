//! One Control-prepared transfer of the original Root lifetime. No retries,
//! privileged executor handle or physical-completion inference. The native
//! recipient alone performs the narrowly scoped same-invocation handoff; this
//! acknowledgement cannot retire power or commit terminal state.
use super::*;
use crate::{
    NativeDisplayCompletionPreparation, NativeDisplayFinalizationReservation,
    NativeDisplayRestorationReservation, NativeDisplayRetirementPreparation,
};
use linura_observation::DisplayNativeHandoffFacts;
use linura_provider_sdk::ComponentDigest;

fn unavailable() -> String {
    "original completion transfer unavailable; no replay".into()
}

impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_original_display_completion(
        &self,
        material: &str,
        terminal_transaction: &str,
        terminal_dispatch: &str,
        control_version: u64,
        control_binding: ComponentDigest,
        retirement_observation: ComponentDigest,
        preparation_digest: ComponentDigest,
        verification_digest: ComponentDigest,
        frames: &DisplayNativeHandoffFacts,
        expires_at_unix_ms: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let intended = linura_core::DisplayFinalizationMaterial::decode(material)
            .map_err(|_| unavailable())?;
        let scope = intended.recovery_scope().map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let binding = control_binding;
        let observation = retirement_observation;
        let preparation = preparation_digest;
        let verification = verification_digest;
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
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadFinalization",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayuay"
            || reply.body().len()
                > crate::MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION
                    + crate::MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION
                    + 64
        {
            return Err(unavailable());
        }
        let (restoration, phase, native): (Vec<u8>, u32, Vec<u8>) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let restoration = NativeDisplayRestorationReservation::decode(&restoration)?;
        let terminal = NativeDisplayFinalizationReservation::decode(&native)?;
        terminal.validate_restoration(&restoration)?;
        if phase != 6
            || terminal.material() != material
            || terminal.binding().transaction_id != terminal_transaction
            || terminal.binding().dispatch_digest.to_hex() != terminal_dispatch
        {
            return Err(unavailable());
        }
        let parent = NativeDisplayRetirementPreparation::new(
            &terminal,
            control_version,
            binding,
            observation,
        )?;
        let record = NativeDisplayCompletionPreparation::new(
            &parent,
            preparation,
            verification,
            frames,
            expires_at_unix_ms,
        )?;
        record.validate_restoration(&restoration)?;
        let bytes = record.canonical_bytes();
        let fingerprint = ComponentDigest::from_bytes(Sha256::digest(&bytes).into());
        // Recheck physical first-frame identity before the single Root grant.
        // Native repeats that check on the same retained scene at consumption.
        let sample = self.observe_native_display_handoff(&scope, 1)?;
        let fresh = DisplayNativeHandoffFacts::from_envelope(&sample, &scope, unix_ms()?)
            .map_err(|_| unavailable())?;
        if fresh.lineage() != frames.lineage()
            || fresh.outputs() != frames.outputs()
            || fresh.window().deadline_unix_ms != window.deadline_unix_ms
            || fresh.window().deadline_boot_ms != window.deadline_boot_ms
            || fresh.window().observed_unix_ms < window.observed_unix_ms
            || fresh.window().observed_boot_ms < window.observed_boot_ms
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        // Irreversible from here: an error never repeats this call or sends
        // the same lifetime to a replacement owner/Root process.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveCompletionGrant",
            &(&bytes,),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "h"
        {
            return Err(unavailable());
        }
        let (descriptor,): (zbus::zvariant::OwnedFd,) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let descriptor: std::os::fd::OwnedFd = descriptor.into();
        let peer = rustix::net::sockopt::socket_peercred(&descriptor).map_err(|_| unavailable())?;
        if peer.uid.as_raw() != 0
            || peer.gid.as_raw() != 0
            || peer.pid.as_raw_nonzero().get() as u32 != root.pid
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        let descriptor = zbus::zvariant::OwnedFd::from(descriptor);
        let bound = terminal.binding();
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "TransferOriginalDisplayCompletion",
            &(
                (
                    material,
                    bound.transaction_id.as_str(),
                    bound.effect_digest.to_hex(),
                    bound.dispatch_digest.to_hex(),
                    expires_at_unix_ms,
                ),
                fingerprint.to_hex(),
                descriptor,
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "u"
        {
            return Err(unavailable());
        }
        let (phase,): (u32,) = reply.body().deserialize().map_err(|_| unavailable())?;
        if phase != 8 {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadCompletion",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION + 32
        {
            return Err(unavailable());
        }
        let (retained, phase): (Vec<u8>, u32) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        if phase != 2
            || retained != bytes
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        current()?;
        Ok(()) // ACK/readback only; Control still needs independent completion.
    }
}
