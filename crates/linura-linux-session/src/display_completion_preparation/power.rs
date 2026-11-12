//! Complete, bounded comparison for one separately prepared native power
//! retirement. It preserves the original Root completion and checkpoint;
//! neither these bytes nor a historical verification digest grants authority.
use super::{append, digest, field, invalid, number};
use crate::NativeDisplayCompletionPreparation;
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayNativeCurrentOutput, DisplayNativeHandoffWindow,
};
use linura_provider_sdk::ComponentDigest;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"linura.native-display.power-retirement.v1";
pub const MAX_NATIVE_DISPLAY_POWER_RETIREMENT: usize =
    crate::MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION + 8 * 1024;

#[derive(Debug)]
pub struct NativeDisplayPowerRetirementPreparation {
    parent: NativeDisplayCompletionPreparation,
    preparation: ComponentDigest,
    checkpoint: ComponentDigest,
    frames: DisplayNativeCurrentFacts,
    expiry: u64,
}
impl NativeDisplayPowerRetirementPreparation {
    pub fn new(
        parent: &NativeDisplayCompletionPreparation,
        preparation: ComponentDigest,
        checkpoint: ComponentDigest,
        frames: &DisplayNativeCurrentFacts,
        expiry: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayCompletionPreparation::decode(&parent.canonical_bytes())?;
        let window = frames.window();
        let end = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if preparation == ComponentDigest::from_bytes([0; 32])
            || checkpoint == ComponentDigest::from_bytes([0; 32])
            || preparation == checkpoint
            || !frames.follows_handoff(parent.frames())
            || frames.completion_digest()
                != ComponentDigest::from_bytes(Sha256::digest(parent.canonical_bytes()).into())
                    .to_hex()
            || !frames.input_retired()
            || !frames.power_fence_held()
            || expiry <= window.observed_unix_ms
            || expiry > end
        {
            return Err(invalid());
        }
        let result = Self {
            parent,
            preparation,
            checkpoint,
            frames: frames.clone(),
            expiry,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_POWER_RETIREMENT {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_POWER_RETIREMENT {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayCompletionPreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION,
        )?)?;
        let preparation = digest(&mut rest)?;
        let checkpoint = digest(&mut rest)?;
        let expiry = number(&mut rest)?;
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        let count = number(&mut rest)?;
        if count != parent.frames().outputs().len() as u64 {
            return Err(invalid());
        }
        let mut outputs = BTreeMap::new();
        for id in parent.frames().outputs().keys() {
            if number(&mut rest)? != id.handle() || number(&mut rest)? != id.generation() {
                return Err(invalid());
            }
            let enabled = match number(&mut rest)? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            let mut kms = [0u32; 4];
            for value in &mut kms {
                *value = u32::try_from(number(&mut rest)?).map_err(|_| invalid())?;
            }
            outputs.insert(
                id.clone(),
                DisplayNativeCurrentOutput {
                    enabled,
                    connector: kms[0],
                    crtc: kms[1],
                    plane: kms[2],
                    framebuffer: kms[3],
                    handoff_commit: number(&mut rest)?,
                    completed_commit: number(&mut rest)?,
                },
            );
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        let frames = DisplayNativeCurrentFacts::new(
            parent.frames().scope().clone(),
            parent.frames().lineage().clone(),
            window,
            outputs,
            ComponentDigest::from_bytes(Sha256::digest(parent.canonical_bytes()).into()).to_hex(),
            true,
            true,
            None,
        )
        .map_err(|_| invalid())?;
        let result = Self::new(&parent, preparation, checkpoint, &frames, expiry)?;
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
            self.checkpoint.to_hex().as_bytes(),
        ] {
            append(&mut out, value);
        }
        let window = self.frames.window();
        for value in [
            self.expiry,
            window.observed_unix_ms,
            window.observed_boot_ms,
            window.deadline_unix_ms,
            window.deadline_boot_ms,
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
                row.handoff_commit,
                row.completed_commit,
            ] {
                append(&mut out, value.to_string().as_bytes());
            }
        }
        out
    }
    pub fn parent(&self) -> &NativeDisplayCompletionPreparation {
        &self.parent
    }
    pub fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub fn preparation_digest(&self) -> &ComponentDigest {
        &self.preparation
    }
    pub fn checkpoint_digest(&self) -> &ComponentDigest {
        &self.checkpoint
    }
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
