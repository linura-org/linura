//! Comparison material for a separately prepared successor. An authenticated
//! ReleasedCurrent parent is necessary, but neither this record nor its hashes
//! can admit a compositor, replace a live witness, or authorize an Apply.
use crate::{NativeDisplayRecoveryCheckpoint, NativeDisplayReleasedCurrentRecord};
use linura_core::{DisplayLayoutMaterial, MAX_DISPLAY_INTENT_BYTES};
use linura_observation::DisplayNativeHandoffWindow;
use linura_provider_sdk::{ComponentDigest, ExecutionBinding, display_layout_effect};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"linura.native-display.successor-preparation.v1";
// Preserve the existing sealed-native-material ceiling. Oversized ancestry
// refuses the operation; this protocol cannot enlarge the descriptor boundary.
pub const MAX_NATIVE_DISPLAY_SUCCESSOR_PREPARATION: usize = 64 * 1024;

#[derive(Debug)]
pub struct NativeDisplaySuccessorPreparation {
    parent: NativeDisplayReleasedCurrentRecord,
    material: String,
    binding: ExecutionBinding,
    checkpoint: ComponentDigest,
    source: ComponentDigest,
    window: DisplayNativeHandoffWindow,
}

impl NativeDisplaySuccessorPreparation {
    /// The new operation must have its own fresh canonical Apply preparation.
    /// This same-invocation mechanism cannot adopt a replacement compositor or
    /// reconstruct the predecessor's original review or credential channel.
    pub fn new(
        parent: &NativeDisplayReleasedCurrentRecord,
        material: &str,
        binding: &ExecutionBinding,
        checkpoint: ComponentDigest,
        source: ComponentDigest,
        window: DisplayNativeHandoffWindow,
    ) -> Result<Self, String> {
        let parent = NativeDisplayReleasedCurrentRecord::decode(&parent.canonical_bytes())?;
        let decoded = DisplayLayoutMaterial::decode(material).map_err(|_| invalid())?;
        let terminal = parent
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .terminal();
        let original = terminal.decoded_material()?;
        binding
            .validate_for(&display_layout_effect(material)?)
            .map_err(|_| invalid())?;
        window.valid_for_ms().map_err(|_| invalid())?;
        if decoded.topology() != original.restoration().replacement().topology()
            || !decoded.continues_after(original.restoration().replacement())
            || decoded.continues_after(&decoded)
            || decoded.lock().epoch() != original.current_lock().epoch()
            || binding.transaction_id == terminal.binding().transaction_id
            || binding.dispatch_digest == terminal.binding().dispatch_digest
            || [
                checkpoint,
                source,
                binding.authority_binding_digest,
                binding.authority_use_digest,
                binding.effect_digest,
                binding.dispatch_digest,
            ]
            .contains(&ComponentDigest::from_bytes([0; 32]))
            || window.observed_unix_ms < parent.window().observed_unix_ms
            || window.observed_boot_ms < parent.window().observed_boot_ms
        {
            return Err(invalid());
        }
        let result = Self {
            parent,
            material: material.into(),
            binding: binding.clone(),
            checkpoint,
            source,
            window,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_SUCCESSOR_PREPARATION {
            return Err(invalid());
        }
        Ok(result)
    }

    /// Root derives the comparison from the actual fresh checkpoint while it
    /// holds admission. The pre-sample BOOTTIME deadline is never restarted by
    /// this later serialization, disk publication, or wall-clock sampling.
    pub fn from_checkpoint(
        parent: &NativeDisplayReleasedCurrentRecord,
        bytes: &[u8],
        now_unix_ms: u64,
        now_boot_ms: u64,
    ) -> Result<Self, String> {
        let dispatch = NativeDisplayRecoveryCheckpoint::stored_dispatch(bytes)?;
        NativeDisplayRecoveryCheckpoint::validate_stored(bytes, &dispatch)?;
        let mut rest = bytes;
        field(&mut rest, 64)?;
        let binding = ExecutionBinding {
            transaction_id: text(&mut rest, 256)?.into(),
            generation: number(&mut rest)?,
            state_version: number(&mut rest)?,
            authority_binding_digest: digest(&mut rest)?,
            authority_use_digest: digest(&mut rest)?,
            effect_digest: digest(&mut rest)?,
            dispatch_digest: digest(&mut rest)?,
        };
        let material = text(&mut rest, MAX_DISPLAY_INTENT_BYTES)?;
        let deadline = number(&mut rest)?;
        for _ in 10..15 {
            field(&mut rest, 256)?;
        }
        let boot = number(&mut rest)?;
        field(&mut rest, 64)?;
        let source = digest(&mut rest)?;
        let elapsed = now_boot_ms
            .checked_sub(boot)
            .filter(|age| *age < 2000)
            .ok_or_else(invalid)?;
        if now_unix_ms == 0 {
            return Err(invalid());
        }
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: now_unix_ms,
            observed_boot_ms: boot,
            deadline_unix_ms: deadline.min(
                now_unix_ms
                    .checked_add(2000 - elapsed)
                    .ok_or_else(invalid)?,
            ),
            deadline_boot_ms: boot.checked_add(2000).ok_or_else(invalid)?,
        };
        let result = Self::new(
            parent,
            material,
            &binding,
            ComponentDigest::from_bytes(Sha256::digest(bytes).into()),
            source,
            window,
        )?;
        result.validate_checkpoint(bytes)?;
        Ok(result)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_SUCCESSOR_PREPARATION {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayReleasedCurrentRecord::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_FINAL_RETIREMENT + 512,
        )?)?;
        let material = text(&mut rest, MAX_DISPLAY_INTENT_BYTES)?;
        let binding = ExecutionBinding {
            transaction_id: text(&mut rest, 256)?.into(),
            generation: number(&mut rest)?,
            state_version: number(&mut rest)?,
            authority_binding_digest: digest(&mut rest)?,
            authority_use_digest: digest(&mut rest)?,
            effect_digest: digest(&mut rest)?,
            dispatch_digest: digest(&mut rest)?,
        };
        let checkpoint = digest(&mut rest)?;
        let source = digest(&mut rest)?;
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        if !rest.is_empty() {
            return Err(invalid());
        }
        let result = Self::new(&parent, material, &binding, checkpoint, source, window)?;
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
            self.material.as_bytes(),
            self.binding.transaction_id.as_bytes(),
            self.binding.generation.to_string().as_bytes(),
            self.binding.state_version.to_string().as_bytes(),
            self.binding.authority_binding_digest.to_hex().as_bytes(),
            self.binding.authority_use_digest.to_hex().as_bytes(),
            self.binding.effect_digest.to_hex().as_bytes(),
            self.binding.dispatch_digest.to_hex().as_bytes(),
            self.checkpoint.to_hex().as_bytes(),
            self.source.to_hex().as_bytes(),
            self.window.observed_unix_ms.to_string().as_bytes(),
            self.window.observed_boot_ms.to_string().as_bytes(),
            self.window.deadline_unix_ms.to_string().as_bytes(),
            self.window.deadline_boot_ms.to_string().as_bytes(),
        ] {
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// Compare the *actual* newly retained Root checkpoint, not a client hash.
    /// Full binding, material and source identity must match the new operation.
    pub fn validate_checkpoint(&self, bytes: &[u8]) -> Result<(), String> {
        NativeDisplayRecoveryCheckpoint::validate_stored(bytes, &self.binding.dispatch_digest)?;
        if ComponentDigest::from_bytes(Sha256::digest(bytes).into()) != self.checkpoint {
            return Err(invalid());
        }
        let mut rest = bytes;
        for expected in [
            b"linura.native-display.recovery-preimage.v1".as_slice(),
            self.binding.transaction_id.as_bytes(),
            self.binding.generation.to_string().as_bytes(),
            self.binding.state_version.to_string().as_bytes(),
            self.binding.authority_binding_digest.to_hex().as_bytes(),
            self.binding.authority_use_digest.to_hex().as_bytes(),
            self.binding.effect_digest.to_hex().as_bytes(),
            self.binding.dispatch_digest.to_hex().as_bytes(),
            self.material.as_bytes(),
        ] {
            if field(&mut rest, 384 * 1024)? != expected {
                return Err(invalid());
            }
        }
        let deadline = number(&mut rest)?;
        for _ in 10..15 {
            field(&mut rest, 256)?;
        }
        let boot = number(&mut rest)?;
        field(&mut rest, 64)?; // Exact sampled-observation digest, retained by its parent.
        if digest(&mut rest)? != self.source
            || boot != self.window.observed_boot_ms
            || deadline < self.window.deadline_unix_ms
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub const fn parent(&self) -> &NativeDisplayReleasedCurrentRecord {
        &self.parent
    }
    pub fn material(&self) -> &str {
        &self.material
    }
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }
    pub const fn checkpoint_digest(&self) -> &ComponentDigest {
        &self.checkpoint
    }
    pub const fn source_guard(&self) -> &ComponentDigest {
        &self.source
    }
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
    pub fn record_digest(&self) -> ComponentDigest {
        ComponentDigest::from_bytes(Sha256::digest(self.canonical_bytes()).into())
    }
}
fn invalid() -> String {
    "native successor preparation is inconsistent; no admission authority".into()
}
fn field<'a>(rest: &mut &'a [u8], maximum: usize) -> Result<&'a [u8], String> {
    let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())?;
    if size == 0 || size > maximum {
        return Err(invalid());
    }
    let (value, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
    *rest = tail;
    Ok(value)
}
fn text<'a>(rest: &mut &'a [u8], max: usize) -> Result<&'a str, String> {
    std::str::from_utf8(field(rest, max)?).map_err(|_| invalid())
}
fn number(rest: &mut &[u8]) -> Result<u64, String> {
    let raw = text(rest, 20)?;
    let n = raw.parse::<u64>().map_err(|_| invalid())?;
    if n.to_string() != raw {
        return Err(invalid());
    }
    Ok(n)
}
fn digest(rest: &mut &[u8]) -> Result<ComponentDigest, String> {
    let raw = text(rest, 64)?;
    let d = ComponentDigest::parse_hex(raw).map_err(|_| invalid())?;
    if d.to_hex() != raw || d == ComponentDigest::from_bytes([0; 32]) {
        return Err(invalid());
    }
    Ok(d)
}
