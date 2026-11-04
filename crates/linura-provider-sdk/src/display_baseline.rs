//! Pure comparison of the canonical native baseline. This digest is a bounded
//! precondition of an already authorized effect, never a credential or plan.
use linura_core::{DisplayLayout, DisplayOutputId, DisplayOutputLayout};
use linura_observation::{DisplayObservationFacts, DisplayRecoveryMetadata};
use std::collections::BTreeMap;

use crate::ComponentDigest;

pub fn display_baseline_guard(facts: &DisplayObservationFacts) -> Result<ComponentDigest, String> {
    let recovery = facts
        .recovery_metadata()
        .ok_or("native baseline ownership evidence is unavailable")?;
    display_layout_source_guard(facts.layout(), recovery)
}

/// Comparison-only guard for a complete layout and source projection. This may
/// describe an independently derived expected postcondition; constructing it
/// never creates an observation, verification result or execution credential.
pub fn display_layout_source_guard(
    layout: &DisplayLayout,
    recovery: &BTreeMap<DisplayOutputId, DisplayRecoveryMetadata>,
) -> Result<ComponentDigest, String> {
    if recovery.len() != layout.outputs().len() || recovery.is_empty() {
        return Err("native source inventory differs from layout".into());
    }
    let canonical = layout.canonical_text().map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    for (output, metadata) in recovery {
        let target = layout
            .outputs()
            .iter()
            .find(|row| row.output() == output)
            .ok_or("native baseline output is absent")?;
        let owned = if !metadata.linura_owned() {
            String::new()
        } else {
            match target {
                DisplayOutputLayout::Disabled { output } => format!(
                    "LNOT:1;{};{};0;0;0;0;0;0;0;0;0;0;",
                    output.handle(),
                    output.generation()
                ),
                DisplayOutputLayout::Enabled {
                    output,
                    mode,
                    scale,
                    transform,
                    x,
                    y,
                    mirror,
                } => {
                    format!(
                        "LNOT:1;{};{};1;{};{};{};{};{};{};{};{};{};",
                        output.handle(),
                        output.generation(),
                        mode.width(),
                        mode.height(),
                        mode.refresh_millihz(),
                        scale.milli(),
                        transform.native_value(),
                        x,
                        y,
                        mirror.as_ref().map_or(0, |output| output.handle()),
                        mirror.as_ref().map_or(0, |output| output.generation())
                    )
                }
            }
        };
        for value in [
            output.handle().to_string(),
            output.generation().to_string(),
            if metadata.linura_owned() {
                "true"
            } else {
                "false"
            }
            .into(),
            metadata.base_configuration_digest().into(),
            metadata.native_identity_digest().into(),
            owned,
        ] {
            rows.extend_from_slice(&(value.len() as u64).to_be_bytes());
            rows.extend_from_slice(value.as_bytes());
        }
    }
    Ok(super::provider_contract::hash_parts(
        b"linura.display.native-baseline-guard.v1",
        &[canonical.as_bytes(), &rows],
    ))
}
