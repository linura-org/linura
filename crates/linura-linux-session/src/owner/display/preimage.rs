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

// An independently bounded validation of the native LNDR:2 representation. The
// root adapter retains exact bytes, and never converts them into an effect.
#[cfg(test)]
fn rule(raw: &str) -> Result<(), String> {
    validate_rule(raw, false)
}

// Old persisted LNDR:1 bytes remain historical data. They have no selector
// lineage and cannot be used to reserve a new attempt or reconstruct a rule.
fn validate_rule(raw: &str, historical: bool) -> Result<(), String> {
    let legacy = historical && raw.starts_with("LNDR:1;");
    if raw.len() > if legacy { 12 * 1024 } else { 20 * 1024 } {
        return Err(invalid());
    }
    let raw = raw
        .strip_prefix(if legacy { "LNDR:1;" } else { "LNDR:2;" })
        .and_then(|v| v.strip_suffix(';'))
        .ok_or_else(invalid)?;
    let fields: Vec<_> = raw.split(';').collect();
    if fields.len() != if legacy { 25 } else { 26 } || !matches!(fields[0], "0" | "1") {
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
    if !legacy && !hex(fields[25], 4096) {
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

// Independent Rust validation of the source-versioned native selection and
// wlr-owned projection. Keep the same 20 KiB per-head cap as LNDR:2.
fn lineage(raw: &str) -> Result<(), String> {
    validate_lineage(raw, false)
}
fn historical_lineage(raw: &str) -> Result<(), String> {
    validate_lineage(raw, true)
}
// Exact comparison projection of RecoveryLineage::replacementProjection. The
// historical bytes are never rewritten. A restored source is explicitly tied
// to THIS checkpoint, not reported as a reconstructed live Wayland client.
fn restored_lineage(raw: &str, checkpoint: &str) -> Result<String, String> {
    lineage(raw)?;
    if !digest(checkpoint) {
        return Err(invalid());
    }
    let body = raw
        .strip_prefix("LNRL:2;")
        .and_then(|v| v.strip_suffix(';'))
        .ok_or_else(invalid)?;
    let mut fields: Vec<_> = body.split(';').collect();
    let count = usize::try_from(number(fields[1])?).map_err(|_| invalid())?;
    if fields[54 + count] != "0" {
        fields[54 + count] = "2";
        fields[57 + count] = checkpoint;
    }
    let projected = format!("LNRL:2;{};", fields.join(";"));
    lineage(&projected)?;
    Ok(projected)
}
fn validate_lineage(raw: &str, historical: bool) -> Result<(), String> {
    let legacy = historical && raw.starts_with("LNRL:1;");
    if raw.len() > 20 * 1024 {
        return Err(invalid());
    }
    let body = raw
        .strip_prefix(if legacy { "LNRL:1;" } else { "LNRL:2;" })
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(invalid)?;
    let fields: Vec<_> = body.split(';').collect();
    if fields.len() < 57 {
        return Err(invalid());
    }
    let selected = usize::try_from(number(fields[0])?).map_err(|_| invalid())?;
    let count = usize::try_from(number(fields[1])?).map_err(|_| invalid())?;
    if count > 256 || selected > count || fields.len() != (if legacy { 57 } else { 58 }) + count {
        return Err(invalid());
    }
    let selectors = &fields[2..2 + count];
    if selectors.iter().any(|value| {
        value.len() > 8192
            || !value.len().is_multiple_of(2)
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err(invalid());
    }
    let native = &fields[2 + count..28 + count];
    let effective = &fields[28 + count..54 + count];
    for rule in [native, effective] {
        validate_rule(&format!("LNDR:2;{};", rule.join(";")), false)?;
    }
    if selected == 0 {
        if !native[25].is_empty() || selectors.contains(&"") {
            return Err(invalid());
        }
    } else if native[25] != selectors[selected - 1] {
        return Err(invalid());
    }
    let wlr = fields[54 + count];
    let mask = number(fields[55 + count])?;
    let refresh = u32::try_from(number(fields[56 + count])?).map_err(|_| invalid())?;
    let origin = if legacy { "" } else { fields[57 + count] };
    if !matches!(wlr, "0" | "1" | "2")
        || legacy && wlr == "2"
        || mask > 31
        || (if wlr == "2" {
            !digest(origin)
        } else {
            !origin.is_empty()
        })
    {
        return Err(invalid());
    }
    if wlr != "0" && mask & 3 != 0 {
        let projected = f64::from(refresh as f32 / 1000_f32);
        if effective[3] != format!("{:016x}", projected.to_bits()) {
            return Err(invalid());
        }
    } else if refresh != 0 {
        return Err(invalid());
    }
    if wlr == "0" {
        if mask != 0 || native != effective {
            return Err(invalid());
        }
    } else if native[7] != effective[7]
        || native[9..] != effective[9..]
        || mask & 3 == 0 && native[1..4] != effective[1..4]
        || mask & 4 == 0 && native[4..6] != effective[4..6]
        || mask & 8 == 0 && native[8] != effective[8]
        || mask & 16 == 0 && native[6] != effective[6]
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate(raw: &str, topology: &str) -> Result<Preimage, String> {
    if raw.is_empty() || raw.len() > MAX_PREIMAGE || topology.len() > 64 * 1024 {
        return Err(invalid());
    }
    let saved: Preimage = serde_json::from_str(raw).map_err(|_| invalid())?;
    let native: Topology = serde_json::from_str(topology).map_err(|_| invalid())?;
    if saved.schema != 2
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
        lineage(&row.base_rule)?;
    }
    Ok(saved)
}

/// Opaque historical preimage for the narrow root mechanism checkpoint. Only a
/// freshly attested prepared native sample can construct it. It grants no effect
/// or restoration authority and must never enter public observations or logs.
pub struct NativeDisplayRecoveryCheckpoint {
    canonical: Vec<u8>,
    dispatch: ComponentDigest,
    kernel_outputs: Vec<[u32; 3]>,
}
impl std::fmt::Debug for NativeDisplayRecoveryCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDisplayRecoveryCheckpoint")
            .field("bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}
impl NativeDisplayRecoveryCheckpoint {
    /// Historical source comparison only. Current output continuity, native
    /// capabilities, caller authorization and single-use admission are checked
    /// separately by the retained Guard and native recipient.
    pub fn validate_restoration_source(
        payload: &[u8],
        reservation: &crate::NativeDisplayRestorationReservation,
    ) -> Result<(), String> {
        let material = reservation.decoded_material()?;
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let facts = Self::original_protection_facts(payload, &scope)?;
        let original = linura_core::DisplayLayoutMaterial::decode(facts.original_material())
            .map_err(|_| invalid())?;
        if facts.checkpoint_digest() != material.original_checkpoint()
            || &original != material.original()
            || facts.outputs().len() != material.mapping().original().outputs().len()
            || facts
                .outputs()
                .keys()
                .any(|output| !material.mapping().original().outputs().contains(output))
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Private native-only projection of the SAME strictly validated immutable
    /// source. The Root-created endpoint authenticates this transfer; these
    /// bytes alone never grant a write or replace canonical observation/history.
    /// Durable LNRJ bytes and their original interpretation remain unchanged.
    pub fn restoration_native_projection(
        payload: &[u8],
        reservation: &crate::NativeDisplayRestorationReservation,
    ) -> Result<Vec<u8>, String> {
        Self::validate_restoration_source(payload, reservation)?;
        let material = reservation.decoded_material()?;
        let mut rest = payload;
        let mut raw = None;
        for index in 0..19 {
            let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            let (field, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
            if index == 18 {
                raw = Some(field);
            }
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        let saved: Preimage =
            serde_json::from_slice(raw.ok_or_else(invalid)?).map_err(|_| invalid())?;
        let mut out = Vec::new();
        let mut field = |text: &str| {
            out.extend_from_slice(&(text.len() as u64).to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        };
        for text in [
            "linura.native-display.restoration-projection.v1",
            &saved.upstream,
            &saved.integration,
            &saved.generation,
            &saved.heads.len().to_string(),
        ] {
            field(text);
        }
        // Emit canonical old-key ordering from the typed bijection, regardless
        // of historical JSON object/array ordering. Every original head is used.
        for (old, new) in material.mapping().outputs() {
            let row = saved
                .heads
                .iter()
                .find(|head| {
                    number(&head.handle).ok() == Some(old.handle())
                        && number(&head.generation).ok() == Some(old.generation())
                })
                .ok_or_else(invalid)?;
            for text in [
                old.handle().to_string(),
                old.generation().to_string(),
                new.handle().to_string(),
                new.generation().to_string(),
                format!(
                    "{}:{}:{}",
                    row.kernel_drm[0], row.kernel_drm[1], row.kernel_drm[2]
                ),
                row.base_rule.clone(),
                if row.linura_owned { "1" } else { "0" }.into(),
                row.owned_target.clone(),
                row.output_identity_digest.clone(),
            ] {
                field(&text);
            }
        }
        if out.is_empty() || out.len() > MAX_CHECKPOINT {
            return Err(invalid());
        }
        Ok(out)
    }

    /// Project only typed historical comparison data after the adapter has
    /// freshly authenticated live independent protection. Raw rule bytes never
    /// enter the canonical observation, public reports or model context.
    pub(crate) fn original_protection_facts(
        payload: &[u8],
        scope: &linura_core::DisplayRecoveryScope,
    ) -> Result<linura_observation::DisplayOriginalProtectionFacts, String> {
        let dispatch =
            ComponentDigest::parse_hex(scope.original_dispatch()).map_err(|_| invalid())?;
        Self::validate_stored(payload, &dispatch)?;
        let mut rest = payload;
        let mut fields = Vec::with_capacity(19);
        for _ in 0..19 {
            let (length, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let length = usize::try_from(u64::from_be_bytes(
                length.try_into().map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
            let (field, tail) = body.split_at_checked(length).ok_or_else(invalid)?;
            fields.push(std::str::from_utf8(field).map_err(|_| invalid())?);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        let material =
            linura_core::DisplayLayoutMaterial::decode(fields[8]).map_err(|_| invalid())?;
        let saved: Preimage = serde_json::from_str(fields[18]).map_err(|_| invalid())?;
        if saved.schema != 2 {
            return Err(invalid());
        }
        let checkpoint_digest =
            ComponentDigest::from_bytes(Sha256::digest(payload).into()).to_hex();
        let mut outputs = BTreeMap::new();
        let mut restored_source_digests = BTreeMap::new();
        for row in saved.heads {
            let id = DisplayOutputId::new(
                material.topology().clone(),
                number(&row.handle)?,
                number(&row.generation)?,
            )
            .map_err(|_| invalid())?;
            let metadata = DisplayRecoveryMetadata::new(
                row.linura_owned,
                ComponentDigest::from_bytes(Sha256::digest(row.base_rule.as_bytes()).into())
                    .to_hex(),
                row.output_identity_digest,
            )
            .map_err(|_| invalid())?;
            let restored = restored_lineage(&row.base_rule, &checkpoint_digest)?;
            restored_source_digests.insert(
                id.clone(),
                ComponentDigest::from_bytes(Sha256::digest(restored.as_bytes()).into()).to_hex(),
            );
            if outputs.insert(id, metadata).is_some() {
                return Err(invalid());
            }
        }
        linura_observation::DisplayOriginalProtectionFacts::new(
            scope.clone(),
            fields[8].into(),
            fields[1].into(),
            checkpoint_digest,
            fields[17].into(),
            saved.integration,
            number(fields[15])?,
            number(fields[9])?,
            outputs,
            restored_source_digests,
        )
        .map_err(|_| invalid())
    }
    /// Historical scope comparison for the retained native startup lease.
    /// This cannot turn history into current evidence or a recovery permit.
    pub fn original_startup_scope(
        payload: &[u8],
        expected: &ComponentDigest,
    ) -> Result<(DisplayTopologyId, ComponentDigest), String> {
        Self::validate_stored(payload, expected)?;
        let mut rest = payload;
        let mut topology = None;
        for index in 0..19 {
            let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            let (field, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
            if index == 8 {
                topology = Some(
                    linura_core::DisplayLayoutMaterial::decode(
                        std::str::from_utf8(field).map_err(|_| invalid())?,
                    )
                    .map_err(|_| invalid())?
                    .topology()
                    .clone(),
                );
            }
            if index == 18 {
                let saved: Preimage = serde_json::from_slice(field).map_err(|_| invalid())?;
                return Ok((
                    topology.ok_or_else(invalid)?,
                    ComponentDigest::parse_hex(&saved.integration).map_err(|_| invalid())?,
                ));
            }
            rest = tail;
        }
        Err(invalid())
    }
    /// Read only the historical dispatch correlation from a bounded private
    /// envelope. This does not construct a prepared checkpoint, validate current
    /// native state, recover a lost witness or grant restoration authority.
    pub fn stored_dispatch(payload: &[u8]) -> Result<ComponentDigest, String> {
        if payload.is_empty() || payload.len() > MAX_CHECKPOINT {
            return Err(invalid());
        }
        let mut remaining = payload;
        let mut dispatch = None;
        for index in 0..19 {
            let (length, body) = remaining.split_at_checked(8).ok_or_else(invalid)?;
            let length = usize::try_from(u64::from_be_bytes(
                length.try_into().map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
            let (field, rest) = body.split_at_checked(length).ok_or_else(invalid)?;
            let field = std::str::from_utf8(field).map_err(|_| invalid())?;
            if index == 0 && field != "linura.native-display.recovery-preimage.v1" {
                return Err(invalid());
            }
            if index == 7 {
                if !digest(field) {
                    return Err(invalid());
                }
                dispatch = Some(ComponentDigest::parse_hex(field).map_err(|_| invalid())?);
            }
            remaining = rest;
        }
        if !remaining.is_empty() {
            return Err(invalid());
        }
        dispatch.ok_or_else(invalid)
    }

    /// Validate historical storage bytes against their complete original
    /// execution binding and native scope. This creates no current observation,
    /// prepared effect, replacement mapping or restoration permission.
    pub fn validate_stored(payload: &[u8], expected: &ComponentDigest) -> Result<(), String> {
        if Self::stored_dispatch(payload)? != *expected {
            return Err(invalid());
        }
        let mut remaining = payload;
        let mut fields = Vec::with_capacity(19);
        for _ in 0..19 {
            let (length, body) = remaining.split_at_checked(8).ok_or_else(invalid)?;
            let length = usize::try_from(u64::from_be_bytes(
                length.try_into().map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
            let (field, rest) = body.split_at_checked(length).ok_or_else(invalid)?;
            fields.push(std::str::from_utf8(field).map_err(|_| invalid())?);
            remaining = rest;
        }
        let parse_digest = |field: &str| {
            if !digest(field) {
                return Err(invalid());
            }
            ComponentDigest::parse_hex(field).map_err(|_| invalid())
        };
        let binding = ExecutionBinding {
            transaction_id: fields[1].into(),
            generation: number(fields[2])?,
            state_version: number(fields[3])?,
            authority_binding_digest: parse_digest(fields[4])?,
            authority_use_digest: parse_digest(fields[5])?,
            effect_digest: parse_digest(fields[6])?,
            dispatch_digest: parse_digest(fields[7])?,
        };
        let effect = linura_provider_sdk::display_layout_effect(fields[8])?;
        binding.validate_for(&effect).map_err(|_| invalid())?;
        let material =
            linura_core::DisplayLayoutMaterial::decode(fields[8]).map_err(|_| invalid())?;
        let boot = linura_core::BootId::new(fields[10]).map_err(|_| invalid())?;
        let owner =
            linura_core::SecurityOwnerInvocationId::new(fields[14]).map_err(|_| invalid())?;
        if number(fields[9])? == 0
            || material.lock().epoch().boot() != &boot
            || !super::super::unique_name(fields[11])
            || number(fields[12])? != u64::from(material.lock().epoch().uid())
            || !(1..=i32::MAX as u64).contains(&number(fields[13])?)
            || material.lock().security_owner_invocation() != &owner
            || number(fields[15])? == 0
        {
            return Err(invalid());
        }
        parse_digest(fields[16])?;
        parse_digest(fields[17])?;
        if fields[18].is_empty() || fields[18].len() > MAX_PREIMAGE {
            return Err(invalid());
        }
        let saved: Preimage = serde_json::from_str(fields[18]).map_err(|_| invalid())?;
        if !matches!(saved.schema, 1 | 2)
            || saved.upstream != "efb50993780079460b0cbed1363e2166a2de1d9f"
            || !digest(&saved.integration)
            || number(&saved.generation)? != material.topology().generation()
            || saved.heads.is_empty()
            || saved.heads.len() > 16
        {
            return Err(invalid());
        }
        let mut handles = BTreeSet::new();
        let mut devices = BTreeSet::new();
        for head in &saved.heads {
            if number(&head.handle)? == 0
                || number(&head.generation)? == 0
                || !handles.insert(&head.handle)
                || head.kernel_drm[0] != 226
                || head.kernel_drm[1] > 63
                || head.kernel_drm[2] == 0
                || !devices.insert(head.kernel_drm)
                || head.owned_target.len() > 512
                || head.linura_owned == head.owned_target.is_empty()
                || !digest(&head.output_identity_digest)
            {
                return Err(invalid());
            }
            if saved.schema == 1 {
                validate_rule(&head.base_rule, true)?;
            } else {
                historical_lineage(&head.base_rule)?;
            }
        }
        Ok(())
    }

    /// Compare an authenticated original prepared transfer with the independent
    /// subscription's pre-sample clock. The returned historical DRM tuples
    /// select only which retained kernel objects to compare, never a write.
    pub fn reservation_kernel_outputs(
        payload: &[u8],
        expected: &ComponentDigest,
        subscription_boot_ms: u64,
    ) -> Result<Vec<[u32; 3]>, String> {
        Self::reservation_at(
            payload,
            expected,
            subscription_boot_ms,
            boot_ms()?,
            unix_ms()?,
            current_boot()?.as_str(),
        )
    }

    fn reservation_at(
        payload: &[u8],
        expected: &ComponentDigest,
        subscription_boot_ms: u64,
        now_boot: u64,
        now: u64,
        boot: &str,
    ) -> Result<Vec<[u32; 3]>, String> {
        Self::validate_stored(payload, expected)?;
        let mut rest = payload;
        let mut fields = Vec::with_capacity(19);
        for _ in 0..19 {
            let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            let (field, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
            fields.push(std::str::from_utf8(field).map_err(|_| invalid())?);
            rest = tail;
        }
        let sampled = number(fields[15])?;
        let deadline = number(fields[9])?;
        if subscription_boot_ms == 0
            || sampled < subscription_boot_ms
            || sampled > now_boot
            || now_boot - sampled >= 2000
            || boot != fields[10]
            || deadline <= now
            || deadline - now > 15_000
        {
            return Err(invalid());
        }
        let saved: Preimage = serde_json::from_str(fields[18]).map_err(|_| invalid())?;
        if saved.schema != 2 {
            return Err(invalid());
        }
        saved
            .heads
            .into_iter()
            .map(|head| {
                lineage(&head.base_rule)?;
                Ok(head.kernel_drm)
            })
            .collect()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn dispatch_digest(&self) -> &ComponentDigest {
        &self.dispatch
    }
    /// Comparison-only kernel identities from the same validated original
    /// sample. They cannot select a new output or authorize restoration.
    pub fn kernel_outputs(&self) -> &[[u32; 3]] {
        &self.kernel_outputs
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
            kernel_outputs: serde_json::from_str::<Preimage>(&sample.recovery_preimage)
                .map_err(|_| invalid())?
                .heads
                .iter()
                .map(|head| head.kernel_drm)
                .collect(),
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
