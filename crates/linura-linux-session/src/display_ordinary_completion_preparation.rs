//! Purpose-separated ordinary completion comparison. Serialized history never
//! reconstructs the original live Root/native peers or protected approval.
use crate::NativeDisplayOrdinaryReleasePreparation;
use crate::display_completion_preparation::{append, digest, field, number, text};
use linura_core::DisplayOutputId;
use linura_observation::{
    DisplayNativeHandoffOutput, DisplayNativeHandoffWindow, DisplayOrdinaryHandoffFacts,
    DisplayOrdinaryHandoffLineage,
};
use linura_provider_sdk::ComponentDigest;
use std::collections::BTreeMap;
const DOMAIN: &[u8] = b"linura.native-display.ordinary-completion.v1";
pub const MAX_NATIVE_DISPLAY_ORDINARY_COMPLETION: usize =
    crate::MAX_NATIVE_DISPLAY_ORDINARY_RELEASE + 8 * 1024;
#[derive(Debug)]
pub struct NativeDisplayOrdinaryCompletionPreparation {
    parent: NativeDisplayOrdinaryReleasePreparation,
    preparation: ComponentDigest,
    verification: ComponentDigest,
    expiry: u64,
    frames: DisplayOrdinaryHandoffFacts,
}
fn invalid() -> String {
    "ordinary completion comparison is inconsistent; no authority".into()
}
impl NativeDisplayOrdinaryCompletionPreparation {
    pub fn new(
        parent: &NativeDisplayOrdinaryReleasePreparation,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        frames: &DisplayOrdinaryHandoffFacts,
        expiry: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayOrdinaryReleasePreparation::decode(&parent.canonical_bytes())?;
        let material = parent.decoded_material()?;
        let binding = parent.binding();
        let lineage = frames.lineage();
        let producer = parent.window();
        let window = frames.window();
        let remaining = window.valid_for_ms().map_err(|_| invalid())?;
        if preparation == ComponentDigest::from_bytes([0; 32])
            || verification == ComponentDigest::from_bytes([0; 32])
            || preparation == verification
            || !frames.matches_material(&material)
            || lineage.release_transaction != binding.transaction_id
            || lineage.release_effect != binding.effect_digest.to_hex()
            || lineage.release_dispatch != binding.dispatch_digest.to_hex()
            || lineage.preparation_digest != parent.record_digest().to_hex()
            || window.observed_unix_ms < producer.observed_unix_ms
            || window.observed_boot_ms < producer.observed_boot_ms
            || window.deadline_unix_ms != producer.deadline_unix_ms
            || window.deadline_boot_ms != producer.deadline_boot_ms
            || expiry <= window.observed_unix_ms
            || expiry
                > window
                    .observed_unix_ms
                    .checked_add(remaining)
                    .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        let result = Self {
            parent,
            preparation,
            verification,
            expiry,
            frames: frames.clone(),
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_ORDINARY_COMPLETION {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_ORDINARY_COMPLETION {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayOrdinaryReleasePreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_ORDINARY_RELEASE,
        )?)?;
        let preparation = digest(&mut rest)?;
        let verification = digest(&mut rest)?;
        let original_transaction = text(&mut rest, 256)?.into();
        let original_effect = digest(&mut rest)?.to_hex();
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        let post_write_epoch = number(&mut rest)?;
        let security_epoch = number(&mut rest)?;
        let expiry = number(&mut rest)?;
        let count = number(&mut rest)?;
        if !(1..=16).contains(&count) {
            return Err(invalid());
        }
        let material = parent.decoded_material()?;
        let scope = material.release_scope().map_err(|_| invalid())?;
        let lineage = DisplayOrdinaryHandoffLineage {
            original_transaction,
            original_effect,
            release_transaction: parent.binding().transaction_id.clone(),
            release_effect: parent.binding().effect_digest.to_hex(),
            release_dispatch: parent.binding().dispatch_digest.to_hex(),
            preparation_digest: parent.record_digest().to_hex(),
            terminal_record: material.lineage().terminal_record.into(),
            checkpoint: material.lineage().original_checkpoint.into(),
            signed_binding: material.lineage().signed_binding.into(),
            source_guard: material.lineage().current_source_guard.into(),
            outcome: material.outcome().as_str().into(),
            post_write_epoch,
            security_epoch,
        };
        let mut outputs = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let output = DisplayOutputId::new(
                scope.topology().clone(),
                number(&mut rest)?,
                number(&mut rest)?,
            )
            .map_err(|_| invalid())?;
            if previous.as_ref().is_some_and(|old| old >= &output) {
                return Err(invalid());
            }
            previous = Some(output.clone());
            let enabled = match number(&mut rest)? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            let mut kms = [0_u32; 4];
            for value in &mut kms {
                *value = u32::try_from(number(&mut rest)?).map_err(|_| invalid())?;
            }
            outputs.insert(
                output,
                DisplayNativeHandoffOutput {
                    enabled,
                    connector: kms[0],
                    crtc: kms[1],
                    plane: kms[2],
                    framebuffer: kms[3],
                    spend_high_water: number(&mut rest)?,
                    completed_commit: number(&mut rest)?,
                },
            );
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        let frames = DisplayOrdinaryHandoffFacts::new(scope, lineage, window, outputs)
            .map_err(|_| invalid())?;
        let result = Self::new(&parent, preparation, verification, &frames, expiry)?;
        if result.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [
            DOMAIN,
            &self.parent.canonical_bytes(),
            self.preparation.to_hex().as_bytes(),
            self.verification.to_hex().as_bytes(),
            self.frames.lineage().original_transaction.as_bytes(),
            self.frames.lineage().original_effect.as_bytes(),
        ] {
            append(&mut out, value);
        }
        let w = self.frames.window();
        for value in [
            w.observed_unix_ms,
            w.observed_boot_ms,
            w.deadline_unix_ms,
            w.deadline_boot_ms,
            self.frames.lineage().post_write_epoch,
            self.frames.lineage().security_epoch,
            self.expiry,
            self.frames.outputs().len() as u64,
        ] {
            append(&mut out, value.to_string().as_bytes());
        }
        for (id, row) in self.frames.outputs() {
            for value in [
                id.handle(),
                id.generation(),
                u64::from(row.enabled),
                u64::from(row.connector),
                u64::from(row.crtc),
                u64::from(row.plane),
                u64::from(row.framebuffer),
                row.spend_high_water,
                row.completed_commit,
            ] {
                append(&mut out, value.to_string().as_bytes());
            }
        }
        out
    }
    /// The original producer is checked separately against its retained kernel,
    /// power and startup witnesses. This compares the complete immutable preimage.
    pub fn validate_original(&self, payload: &[u8]) -> Result<(), String> {
        self.parent.validate_original(payload)?;
        let scope = self
            .parent
            .decoded_material()?
            .release_scope()
            .map_err(|_| invalid())?;
        let original =
            crate::NativeDisplayRecoveryCheckpoint::ordinary_original_facts(payload, &scope)?;
        if self.frames.lineage().original_transaction != original.comparison().transaction
            || self.frames.lineage().original_effect
                != linura_provider_sdk::display_layout_effect(&original.comparison().material)?
                    .digest()
                    .to_hex()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub const fn parent(&self) -> &NativeDisplayOrdinaryReleasePreparation {
        &self.parent
    }
    pub const fn frames(&self) -> &DisplayOrdinaryHandoffFacts {
        &self.frames
    }
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }
    pub const fn preparation(&self) -> &ComponentDigest {
        &self.preparation
    }
    pub const fn verification(&self) -> &ComponentDigest {
        &self.verification
    }
    pub fn record_digest(&self) -> ComponentDigest {
        use sha2::{Digest, Sha256};
        ComponentDigest::from_bytes(Sha256::digest(self.canonical_bytes()).into())
    }
}
