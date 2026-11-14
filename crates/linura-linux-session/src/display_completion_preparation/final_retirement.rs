//! Final original display-fence retirement comparison, after independently
//! verified committed-current qualification. Complete parent ancestry and
//! actual current KMS/input/power remain required; these bytes are not authority.
use super::current_commit::NativeDisplayCurrentCommitPreparation;
use super::{append, digest, field, invalid, number};
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayNativeCurrentOutput, DisplayNativeHandoffWindow,
};
use linura_provider_sdk::ComponentDigest;
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"linura.native-display.final-retirement.v1";
pub const MAX_NATIVE_DISPLAY_FINAL_RETIREMENT: usize =
    crate::MAX_NATIVE_DISPLAY_CURRENT_COMMIT + 8 * 1024;

#[derive(Debug)]
pub struct NativeDisplayFinalRetirementPreparation {
    parent: NativeDisplayCurrentCommitPreparation,
    preparation: ComponentDigest,
    verification: ComponentDigest,
    frames: DisplayNativeCurrentFacts,
    expiry: u64,
}
impl NativeDisplayFinalRetirementPreparation {
    pub fn new(
        parent: &NativeDisplayCurrentCommitPreparation,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        frames: &DisplayNativeCurrentFacts,
        expiry: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayCurrentCommitPreparation::decode(&parent.canonical_bytes())?;
        let window = frames.window();
        let end = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if preparation == ComponentDigest::from_bytes([0; 32])
            || verification == ComponentDigest::from_bytes([0; 32])
            || preparation == verification
            || !frames.follows_current_qualification(parent.frames())
            || frames.current_commit_digest() != Some(parent.record_digest().to_hex().as_str())
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
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_FINAL_RETIREMENT {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_FINAL_RETIREMENT {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayCurrentCommitPreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_CURRENT_COMMIT,
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
            Some(parent.record_digest().to_hex()),
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
    pub fn parent(&self) -> &NativeDisplayCurrentCommitPreparation {
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

/// Root's durable acknowledgement of Control's independent post-retirement
/// proof. This comparison record is neither a native grant nor cleanup authority.
#[derive(Debug)]
pub struct NativeDisplayReleasedCurrentRecord {
    parent: NativeDisplayFinalRetirementPreparation,
    verification: ComponentDigest,
    window: DisplayNativeHandoffWindow,
}
impl NativeDisplayReleasedCurrentRecord {
    const DOMAIN: &[u8] = b"linura.native-display.released-current.v1";
    pub fn new(
        parent: &NativeDisplayFinalRetirementPreparation,
        verification: ComponentDigest,
        window: DisplayNativeHandoffWindow,
    ) -> Result<Self, String> {
        window.valid_for_ms().map_err(|_| invalid())?;
        if verification == ComponentDigest::from_bytes([0; 32])
            || window.observed_unix_ms < parent.frames().window().observed_unix_ms
            || window.observed_boot_ms < parent.frames().window().observed_boot_ms
        {
            return Err(invalid());
        }
        Ok(Self {
            parent: NativeDisplayFinalRetirementPreparation::decode(&parent.canonical_bytes())?,
            verification,
            window,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_FINAL_RETIREMENT + 512 {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, Self::DOMAIN.len())? != Self::DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayFinalRetirementPreparation::decode(field(
            &mut rest,
            MAX_NATIVE_DISPLAY_FINAL_RETIREMENT,
        )?)?;
        let verification = digest(&mut rest)?;
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        if !rest.is_empty() {
            return Err(invalid());
        }
        let result = Self::new(&parent, verification, window)?;
        if result.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            Self::DOMAIN,
            &self.parent.canonical_bytes(),
            self.verification.to_hex().as_bytes(),
        ] {
            append(&mut bytes, value);
        }
        for value in [
            self.window.observed_unix_ms,
            self.window.observed_boot_ms,
            self.window.deadline_unix_ms,
            self.window.deadline_boot_ms,
        ] {
            append(&mut bytes, value.to_string().as_bytes());
        }
        bytes
    }
    pub fn parent(&self) -> &NativeDisplayFinalRetirementPreparation {
        &self.parent
    }
    pub const fn verification_digest(&self) -> &ComponentDigest {
        &self.verification
    }
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
}
