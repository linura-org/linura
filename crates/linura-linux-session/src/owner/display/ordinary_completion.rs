//! Single supervised Root/native ordinary completion. The ACK proves neither
//! independent current frames nor input/power/startup retirement.
use super::*;
use crate::{NativeDisplayOrdinaryCompletionPreparation, NativeDisplayOrdinaryReleasePreparation};
use linura_observation::DisplayOrdinaryHandoffFacts;
use linura_provider_sdk::ComponentDigest;

fn unavailable() -> String {
    "ordinary completion transfer unavailable; no replay".into()
}

impl NativeSessionChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_ordinary_display_completion(
        &self,
        material: &str,
        transaction: &str,
        dispatch: &str,
        root_preparation: &str,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        frames: &DisplayOrdinaryHandoffFacts,
        expiry: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let intent = linura_core::DisplayOrdinaryReleaseMaterial::decode(material)
            .map_err(|_| unavailable())?;
        let scope = intent.release_scope().map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let window = frames.window();
        let current = || {
            let (wall, boot) = (unix_ms()?, boot_ms()?);
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
        let started = Instant::now();
        let boot = current_boot()?;
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let owner = self.discover(scope.topology().session().uid(), started)?;
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadOrdinaryRelease",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayb"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_ORDINARY_RELEASE + 32
        {
            return Err(unavailable());
        }
        let (bytes, spent): (Vec<u8>, bool) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let parent = NativeDisplayOrdinaryReleasePreparation::decode(&bytes)?;
        if !spent
            || parent.material() != material
            || parent.binding().transaction_id != transaction
            || parent.binding().dispatch_digest.to_hex() != dispatch
            || parent.record_digest().to_hex() != root_preparation
        {
            return Err(unavailable());
        }
        let record = NativeDisplayOrdinaryCompletionPreparation::new(
            &parent,
            preparation,
            verification,
            frames,
            expiry,
        )?;
        let encoded = record.canonical_bytes();
        let fingerprint = record.record_digest();
        let sample = self.observe_ordinary_display_handoff(&scope, 1)?;
        let fresh = DisplayOrdinaryHandoffFacts::from_envelope(&sample, &scope, unix_ms()?)
            .map_err(|_| unavailable())?;
        if !fresh.reconciles(frames) {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        current()?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        // After this reservation, every failure is observation-only. Never
        // repeat it or transfer the endpoint to a newly discovered owner.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveOrdinaryCompletionGrant",
            &(&encoded,),
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
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "TransferOrdinaryDisplayCompletion",
            &(
                (
                    material,
                    transaction,
                    parent.binding().effect_digest.to_hex(),
                    dispatch,
                    expiry,
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
            "ReadOrdinaryCompletion",
            &(key.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_ORDINARY_COMPLETION + 32
        {
            return Err(unavailable());
        }
        let (retained, phase): (Vec<u8>, u32) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        if phase != 2
            || retained != encoded
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err(unavailable());
        }
        current()?;
        Ok(())
    }
}
