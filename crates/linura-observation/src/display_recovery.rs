//! Fresh original-witness observation over the canonical envelope. Historical
//! intent and native comparison metadata remain explicitly historical. This
//! provider performs no current-output aggregation, planning or restoration.
use std::collections::BTreeMap;

use linura_core::{DisplayLayoutMaterial, DisplayOutputId, DisplayRecoveryScope};

use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DisplayEvidenceError, DisplayRecoveryMetadata, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};

pub const DISPLAY_RECOVERY_PROVIDER: &str = "hyprland-recovery";
pub const DISPLAY_ORIGINAL_PROTECTION_CAPABILITY: &str = "display.original-protection.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalProtectionFacts {
    scope: DisplayRecoveryScope,
    original_material: String,
    original_transaction: String,
    checkpoint_digest: String,
    native_guard: String,
    integration_digest: String,
    sampled_boot_ms: u64,
    confirmation_deadline_unix_ms: u64,
    outputs: BTreeMap<DisplayOutputId, DisplayRecoveryMetadata>,
    restored_source_digests: BTreeMap<DisplayOutputId, String>,
}

impl DisplayOriginalProtectionFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DisplayRecoveryScope,
        original_material: String,
        original_transaction: String,
        checkpoint_digest: String,
        native_guard: String,
        integration_digest: String,
        sampled_boot_ms: u64,
        confirmation_deadline_unix_ms: u64,
        outputs: BTreeMap<DisplayOutputId, DisplayRecoveryMetadata>,
        restored_source_digests: BTreeMap<DisplayOutputId, String>,
    ) -> Result<Self, DisplayEvidenceError> {
        let material = DisplayLayoutMaterial::decode(&original_material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        let old = material.topology();
        let current = scope.replacement();
        if old.session().boot() != current.session().boot()
            || old.session().uid() != current.session().uid()
            || old.seat() != current.seat()
            || old.compositor() == current.compositor()
            || outputs.is_empty()
            || outputs.len() > 16
            || outputs.keys().any(|id| id.topology() != old)
            || !outputs.keys().eq(restored_source_digests.keys())
            || restored_source_digests
                .values()
                .any(|value| !canonical_digest(value))
        {
            return Err(DisplayEvidenceError::Identity);
        }
        // Reuse the exact native comparison digest validator; no digest grants
        // authority or substitutes for the original retained live witnesses.
        if [&checkpoint_digest, &native_guard, &integration_digest]
            .into_iter()
            .any(|value| !canonical_digest(value))
        {
            return Err(DisplayEvidenceError::Shape);
        }
        if original_transaction.is_empty()
            || original_transaction.len() > 256
            || original_transaction.chars().any(char::is_control)
            || sampled_boot_ms == 0
            || confirmation_deadline_unix_ms == 0
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let mut identities = std::collections::BTreeSet::new();
        let mut handles = std::collections::BTreeSet::new();
        for (output, metadata) in &outputs {
            if !handles.insert(output.handle())
                || !identities.insert(metadata.native_identity_digest())
            {
                return Err(DisplayEvidenceError::Identity);
            }
        }
        Ok(Self {
            scope,
            original_material,
            original_transaction,
            checkpoint_digest,
            native_guard,
            integration_digest,
            sampled_boot_ms,
            confirmation_deadline_unix_ms,
            outputs,
            restored_source_digests,
        })
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attrs = BTreeMap::from([
            ("original_protection_schema".into(), ObservedValue::U64(2)),
            (
                "original_material".into(),
                ObservedValue::Text(self.original_material.clone()),
            ),
            (
                "original_transaction".into(),
                ObservedValue::Text(self.original_transaction.clone()),
            ),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            (
                "original_checkpoint_digest".into(),
                ObservedValue::Text(self.checkpoint_digest.clone()),
            ),
            (
                "original_native_guard".into(),
                ObservedValue::Text(self.native_guard.clone()),
            ),
            (
                "original_integration_digest".into(),
                ObservedValue::Text(self.integration_digest.clone()),
            ),
            (
                "original_sampled_boot_ms".into(),
                ObservedValue::U64(self.sampled_boot_ms),
            ),
            (
                "original_confirmation_deadline_unix_ms".into(),
                ObservedValue::U64(self.confirmation_deadline_unix_ms),
            ),
            (
                "original_output_count".into(),
                ObservedValue::U64(self.outputs.len() as u64),
            ),
        ]);
        for (index, (output, metadata)) in self.outputs.iter().enumerate() {
            let prefix = format!("original_output.{index}");
            for (key, value) in [
                ("handle", ObservedValue::U64(output.handle())),
                ("generation", ObservedValue::U64(output.generation())),
                ("linura_owned", ObservedValue::Bool(metadata.linura_owned())),
                (
                    "base_configuration_digest",
                    ObservedValue::Text(metadata.base_configuration_digest().into()),
                ),
                (
                    "native_identity_digest",
                    ObservedValue::Text(metadata.native_identity_digest().into()),
                ),
                (
                    "restored_source_digest",
                    ObservedValue::Text(self.restored_source_digests[output].clone()),
                ),
            ] {
                attrs.insert(format!("{prefix}.{key}"), value);
            }
        }
        attrs
    }

    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORIGINAL_PROTECTION_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if observation.observed_at_unix_ms == 0
            || observation.valid_for_ms == 0
            || observation.valid_for_ms > 2000
            || observation
                .observed_at_unix_ms
                .checked_add(observation.valid_for_ms)
                .is_none()
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        Self::from_comparison_attributes(&observation.attributes, scope)
    }

    // Comparison-only parser for a separately authenticated, phase-specific
    // Root observation. It cannot manufacture a native held-power envelope.
    pub(crate) fn from_comparison_attributes(
        attrs: &BTreeMap<String, ObservedValue>,
        scope: &DisplayRecoveryScope,
    ) -> Result<Self, DisplayEvidenceError> {
        if attrs.len() > 106
            || number(attrs, "original_protection_schema")? != 2
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "original_output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let material = DisplayLayoutMaterial::decode(text(attrs, "original_material")?)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        let mut outputs = BTreeMap::new();
        let mut restored_source_digests = BTreeMap::new();
        for index in 0..count {
            let prefix = format!("original_output.{index}");
            let output = DisplayOutputId::new(
                material.topology().clone(),
                number(attrs, &format!("{prefix}.handle"))?,
                number(attrs, &format!("{prefix}.generation"))?,
            )
            .map_err(|_| DisplayEvidenceError::Identity)?;
            let metadata = DisplayRecoveryMetadata::new(
                boolean(attrs, &format!("{prefix}.linura_owned"))?,
                text(attrs, &format!("{prefix}.base_configuration_digest"))?.into(),
                text(attrs, &format!("{prefix}.native_identity_digest"))?.into(),
            )?;
            restored_source_digests.insert(
                output.clone(),
                text(attrs, &format!("{prefix}.restored_source_digest"))?.into(),
            );
            if outputs.insert(output, metadata).is_some() {
                return Err(DisplayEvidenceError::Identity);
            }
        }
        let result = Self::new(
            scope.clone(),
            text(attrs, "original_material")?.into(),
            text(attrs, "original_transaction")?.into(),
            text(attrs, "original_checkpoint_digest")?.into(),
            text(attrs, "original_native_guard")?.into(),
            text(attrs, "original_integration_digest")?.into(),
            number(attrs, "original_sampled_boot_ms")?,
            number(attrs, "original_confirmation_deadline_unix_ms")?,
            outputs,
            restored_source_digests,
        )?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }

    #[must_use]
    pub const fn scope(&self) -> &DisplayRecoveryScope {
        &self.scope
    }
    #[must_use]
    pub fn original_material(&self) -> &str {
        &self.original_material
    }
    #[must_use]
    pub fn original_transaction(&self) -> &str {
        &self.original_transaction
    }
    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }
    #[must_use]
    pub fn native_guard(&self) -> &str {
        &self.native_guard
    }
    #[must_use]
    pub fn integration_digest(&self) -> &str {
        &self.integration_digest
    }
    #[must_use]
    pub const fn confirmation_deadline_unix_ms(&self) -> u64 {
        self.confirmation_deadline_unix_ms
    }
    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayRecoveryMetadata> {
        &self.outputs
    }
    /// Expected source hashes mechanically projected from the immutable original
    /// checkpoint, never from the replacement's desired or current rule cache.
    /// The authenticated adapter supplies comparison facts, not release authority.
    #[must_use]
    pub const fn restored_source_digests(&self) -> &BTreeMap<DisplayOutputId, String> {
        &self.restored_source_digests
    }
}

#[cfg(test)]
mod tests;
