//! Exact bounded preparation for retiring Root's independent power witness.
//! The complete original power parent and independently compared native-power
//! absence are required. Comparison bytes never authorize a release themselves.
use super::power::NativeDisplayPowerRetirementPreparation;
use super::{append, digest, field, invalid, number};
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayNativeCurrentOutput, DisplayNativeHandoffWindow,
};
use linura_provider_sdk::ComponentDigest;
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"linura.native-display.root-retirement.v1";
pub const MAX_NATIVE_DISPLAY_ROOT_RETIREMENT: usize =
    crate::MAX_NATIVE_DISPLAY_POWER_RETIREMENT + 8 * 1024;

#[derive(Debug)]
pub struct NativeDisplayRootRetirementPreparation {
    parent: NativeDisplayPowerRetirementPreparation,
    preparation: ComponentDigest,
    verification: ComponentDigest,
    frames: DisplayNativeCurrentFacts,
    expiry: u64,
}
impl NativeDisplayRootRetirementPreparation {
    pub fn new(
        parent: &NativeDisplayPowerRetirementPreparation,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        frames: &DisplayNativeCurrentFacts,
        expiry: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayPowerRetirementPreparation::decode(&parent.canonical_bytes())?;
        let window = frames.window();
        let end = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if preparation == ComponentDigest::from_bytes([0; 32])
            || verification == ComponentDigest::from_bytes([0; 32])
            || preparation == verification
            || !frames.follows_native_power_retirement(parent.frames())
            || frames.completion_digest() != parent.frames().completion_digest()
            || !frames.input_retired()
            || frames.power_fence_held()
            || expiry <= window.observed_unix_ms
            || expiry > end
        {
            return Err(invalid());
        }
        let result = Self {
            parent,
            preparation,
            verification,
            frames: frames.clone(),
            expiry,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_ROOT_RETIREMENT {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_ROOT_RETIREMENT {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayPowerRetirementPreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_POWER_RETIREMENT,
        )?)?;
        let preparation = digest(&mut rest)?;
        let verification = digest(&mut rest)?;
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
            parent.frames().completion_digest().into(),
            true,
            false,
            None,
            None,
        )
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
    pub fn parent(&self) -> &NativeDisplayPowerRetirementPreparation {
        &self.parent
    }
    pub fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub fn preparation_digest(&self) -> &ComponentDigest {
        &self.preparation
    }
    pub fn verification_digest(&self) -> &ComponentDigest {
        &self.verification
    }
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
