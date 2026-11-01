//! Private historical native preimages. None of these bytes are an executor
//! capability, current observation, restoration command or continuity proof.
use super::*;
use linura_provider_sdk::{ComponentDigest, ExecutionBinding};
use serde::Serialize;

const MAX_PREIMAGE: usize = 256 * 1024;
const MAX_CHECKPOINT: usize = 384 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preimage {
    schema: u32,
    upstream: String,
    integration: String,
    generation: String,
    heads: Vec<PreimageHead>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreimageHead {
    handle: String,
    generation: String,
    kernel_drm: [u32; 3],
    base_rule: String,
    linura_owned: bool,
    owned_target: String,
    output_identity_digest: String,
}

fn invalid() -> String {
    "native display recovery preimage is missing, inconsistent or unsupported".into()
}
fn digest(text: &str) -> bool {
    ComponentDigest::parse_hex(text)
        .is_ok_and(|digest| digest.to_hex() == text && text != "0".repeat(64))
}

// An independently bounded validation of the native LNDR:1 representation. The
// root adapter retains exact bytes, and never converts them into an effect.
fn rule(raw: &str) -> Result<(), String> {
    if raw.len() > 12 * 1024 {
        return Err(invalid());
    }
    let raw = raw
        .strip_prefix("LNDR:1;")
        .and_then(|v| v.strip_suffix(';'))
        .ok_or_else(invalid)?;
    let fields: Vec<_> = raw.split(';').collect();
    if fields.len() != 25 || !matches!(fields[0], "0" | "1") {
        return Err(invalid());
    }
    for (i, field) in fields.iter().enumerate().take(7).skip(1) {
        if field.len() != 16
            || !field
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid());
        }
        let bits = u64::from_str_radix(field, 16).map_err(|_| invalid())?;
        let value = f64::from_bits(bits);
        if !value.is_finite()
            || value == 0.0 && bits != 0
            || matches!(i, 3 | 6) && f64::from(value as f32) != value
        {
            return Err(invalid());
        }
    }
    if number(fields[7])? > 8 || number(fields[8])? > 7 {
        return Err(invalid());
    }
    let hex = |value: &str, max: usize| {
        value.len() <= max * 2
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    };
    if !hex(fields[9], 4096) || !hex(fields[24], 32) || fields[24].len() != 64 {
        return Err(invalid());
    }
    for (i, field) in fields.iter().enumerate().take(24).skip(10) {
        if number(field)?
            > if (11..=20).contains(&i) {
                u64::from(u16::MAX)
            } else {
                u64::from(u32::MAX)
            }
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate(raw: &str, topology: &str) -> Result<Preimage, String> {
    if raw.is_empty() || raw.len() > MAX_PREIMAGE || topology.len() > 64 * 1024 {
        return Err(invalid());
    }
    let saved: Preimage = serde_json::from_str(raw).map_err(|_| invalid())?;
    let native: Topology = serde_json::from_str(topology).map_err(|_| invalid())?;
    if saved.schema != 1
        || saved.upstream != "efb50993780079460b0cbed1363e2166a2de1d9f"
        || !digest(&saved.integration)
        || number(&saved.generation)? == 0
        || saved.generation != native.generation
        || saved.heads.is_empty()
        || saved.heads.len() > 16
        || saved.heads.len() != native.heads.len()
    {
        return Err(invalid());
    }
    let mut handles = BTreeSet::new();
    let mut devices = BTreeSet::new();
    for row in &saved.heads {
        let head = native
            .heads
            .iter()
            .find(|head| head.handle == row.handle && head.generation == row.generation)
            .ok_or_else(invalid)?;
        if number(&row.handle)? == 0
            || number(&row.generation)? == 0
            || !handles.insert(&row.handle)
            || row.kernel_drm[0] != 226
            || row.kernel_drm[1] > 63
            || row.kernel_drm[2] == 0
            || row.kernel_drm != head.kernel_drm
            || !devices.insert(row.kernel_drm)
            || row.linura_owned != head.linura_owned
            || row.owned_target != head.owned_target
            || row.output_identity_digest != head.output_identity_digest
            || row.owned_target.len() > 512
            || !digest(&row.output_identity_digest)
            || ComponentDigest::from_bytes(Sha256::digest(row.base_rule.as_bytes()).into()).to_hex()
                != head.base_rule_digest
        {
            return Err(invalid());
        }
        rule(&row.base_rule)?;
    }
    Ok(saved)
}

/// Opaque historical preimage for the narrow root mechanism checkpoint. Only a
/// freshly attested prepared native sample can construct it. It grants no effect
/// or restoration authority and must never enter public observations or logs.
pub struct NativeDisplayRecoveryCheckpoint {
    canonical: Vec<u8>,
    dispatch: ComponentDigest,
}
impl std::fmt::Debug for NativeDisplayRecoveryCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDisplayRecoveryCheckpoint")
            .field("bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}
impl NativeDisplayRecoveryCheckpoint {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn dispatch_digest(&self) -> &ComponentDigest {
        &self.dispatch
    }
    pub(super) fn capture(
        material: &str,
        binding: &ExecutionBinding,
        deadline: u64,
        sample: &PreparedSample,
    ) -> Result<Self, String> {
        let mut canonical = Vec::new();
        for field in [
            "linura.native-display.recovery-preimage.v1",
            binding.transaction_id.as_str(),
            &binding.generation.to_string(),
            &binding.state_version.to_string(),
            &binding.authority_binding_digest.to_hex(),
            &binding.authority_use_digest.to_hex(),
            &binding.effect_digest.to_hex(),
            &binding.dispatch_digest.to_hex(),
            material,
            &deadline.to_string(),
            sample.boot.as_str(),
            sample.owner.unique_name.as_str(),
            &sample.owner.uid.to_string(),
            &sample.owner.pid.to_string(),
            sample.owner.invocation.as_str(),
            &sample.sampled_boot_ms.to_string(),
            &sample.digest.to_hex(),
            &sample
                .native_baseline_guard
                .as_ref()
                .ok_or_else(invalid)?
                .to_hex(),
            sample.recovery_preimage.as_str(),
        ] {
            canonical.extend_from_slice(&(field.len() as u64).to_be_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        if canonical.len() > MAX_CHECKPOINT {
            return Err(invalid());
        }
        Ok(Self {
            canonical,
            dispatch: binding.dispatch_digest,
        })
    }
}

pub(super) fn checked(raw: String, topology: &str) -> Result<String, String> {
    let mut saved = validate(&raw, topology)?;
    saved.heads.sort_by(|a, b| a.handle.cmp(&b.handle));
    serde_json::to_string(&saved).map_err(|_| invalid())
}

#[cfg(test)]
mod tests;
