//! Complete original committed-current comparison. It carries no authority:
//! the original credential-checked Root channel must separately spend its digest.
use super::root_retirement::NativeDisplayRootRetirementPreparation;
use super::{append, digest, field, invalid, number};
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayNativeCurrentOutput, DisplayNativeHandoffWindow,
};
use linura_provider_sdk::ComponentDigest;
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"linura.native-display.current-commit.v1";
pub const MAX_NATIVE_DISPLAY_CURRENT_COMMIT: usize =
    crate::MAX_NATIVE_DISPLAY_ROOT_RETIREMENT + 8 * 1024;

#[derive(Debug)]
pub struct NativeDisplayCurrentCommitPreparation {
    parent: NativeDisplayRootRetirementPreparation,
    preparation: ComponentDigest,
    committed_record: ComponentDigest,
    control_generation: u64,
    control_version: u64,
    control_binding: ComponentDigest,
    frames: DisplayNativeCurrentFacts,
    expiry: u64,
}
impl NativeDisplayCurrentCommitPreparation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: &NativeDisplayRootRetirementPreparation,
        preparation: ComponentDigest,
        committed_record: ComponentDigest,
        control_generation: u64,
        control_version: u64,
        control_binding: ComponentDigest,
        frames: &DisplayNativeCurrentFacts,
        expiry: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayRootRetirementPreparation::decode(&parent.canonical_bytes())?;
        let window = frames.window();
        let end = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        let original = parent.parent().parent().parent();
        if control_generation != original.terminal().binding().generation
            || original.control_state_version().checked_add(2) != Some(control_version)
            || control_binding != *original.control_binding()
            || preparation == ComponentDigest::from_bytes([0; 32])
            || committed_record == ComponentDigest::from_bytes([0; 32])
            || preparation == committed_record
            || !frames.reconciles(parent.frames())
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
            committed_record,
            control_generation,
            control_version,
            control_binding,
            frames: frames.clone(),
            expiry,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_CURRENT_COMMIT {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_CURRENT_COMMIT {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayRootRetirementPreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_ROOT_RETIREMENT,
        )?)?;
        let preparation = digest(&mut rest)?;
        let committed_record = digest(&mut rest)?;
        let control_generation = number(&mut rest)?;
        let control_version = number(&mut rest)?;
        let control_binding = digest(&mut rest)?;
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
        )
        .map_err(|_| invalid())?;
        let result = Self::new(
            &parent,
            preparation,
            committed_record,
            control_generation,
            control_version,
            control_binding,
            &frames,
            expiry,
        )?;
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
            self.committed_record.to_hex().as_bytes(),
            self.control_generation.to_string().as_bytes(),
            self.control_version.to_string().as_bytes(),
            self.control_binding.to_hex().as_bytes(),
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
    pub fn parent(&self) -> &NativeDisplayRootRetirementPreparation {
        &self.parent
    }
    pub fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub fn preparation_digest(&self) -> &ComponentDigest {
        &self.preparation
    }
    pub fn committed_record_digest(&self) -> &ComponentDigest {
        &self.committed_record
    }
    pub fn control_generation(&self) -> u64 {
        self.control_generation
    }
    pub fn control_version(&self) -> u64 {
        self.control_version
    }
    pub fn control_binding(&self) -> &ComponentDigest {
        &self.control_binding
    }
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
