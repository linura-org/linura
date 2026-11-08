//! One independent retained-protection probe. Control owns current-output,
//! session and coverage queries and their cross-provider join/authorization.
use std::sync::atomic::{AtomicU64, Ordering};

use linura_core::{
    Capability, CapabilityId, DisplayRecoveryScope, ProviderId, ResourceId, SupportLevel,
};
use linura_observation::{
    DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY, DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
    DISPLAY_RECOVERY_PROVIDER, ObservationEnvelope, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Debug)]
pub struct NativeOriginalDisplayObserver {
    channel: NativeSessionChannel,
    sequence: AtomicU64,
}
impl NativeOriginalDisplayObserver {
    pub fn new(channel: NativeSessionChannel) -> Result<Self, String> {
        channel.require_role(NativeSessionRole::Control)?;
        Ok(Self {
            channel,
            sequence: AtomicU64::new(0),
        })
    }
}
impl Observer for NativeOriginalDisplayObserver {
    fn observer_id(&self) -> ProviderId {
        ProviderId::new(DISPLAY_RECOVERY_PROVIDER)
            .unwrap_or_else(|e| unreachable!("fixed provider: {e}"))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        [
            DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
            DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
        ]
        .into_iter()
        .map(|capability| Capability {
            id: CapabilityId::new(capability)
                .unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: Some("retained original protection probe; no restoration authority".into()),
        })
        .collect()
    }
    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        matches!(
            capability.as_str(),
            DISPLAY_ORIGINAL_PROTECTION_CAPABILITY | DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
        )
    }
    fn requires_live_health_preflight(&self) -> bool {
        false
    }
    fn health(&self) -> ProviderHealth {
        let result = self.channel.require_role(NativeSessionRole::Control);
        ProviderHealth {
            provider: self.observer_id(),
            availability: if result.is_ok() {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::Unavailable
            },
            reason: result.err(),
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Err(ProviderError::Unsupported(
            "original protection requires an exact retained-attempt and replacement scope".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "original protection capability is unsupported".into(),
            ));
        }
        let scope = DisplayRecoveryScope::from_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                ProviderError::Unavailable("original display protection sequence exhausted".into())
            })?;
        let result = if capability.as_str() == DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY {
            self.channel
                .observe_original_display_finalization(&scope, sequence + 1)
        } else {
            self.channel
                .observe_original_display_protection(&scope, sequence + 1)
        };
        result.map_err(ProviderError::Unavailable)
    }
}

pub(crate) fn finalization_facts(
    scope: &DisplayRecoveryScope,
    restoration: &[u8],
    phase: u32,
    terminal: &[u8],
) -> Result<linura_observation::DisplayOriginalFinalizationFacts, String> {
    use linura_observation::{
        DisplayFinalizationPhase, DisplayFinalizationReservationFacts,
        DisplayOriginalFinalizationFacts,
    };
    let record = crate::NativeDisplayRestorationReservation::decode(restoration)?;
    let material = record.decoded_material()?;
    if material.recovery_scope().map_err(|e| e.to_string())? != *scope {
        return Err("original finalization reservation has another recovery scope".into());
    }
    let phase = match phase {
        0 => DisplayFinalizationPhase::Protected,
        1 => DisplayFinalizationPhase::Reserved,
        2 => DisplayFinalizationPhase::Quiesced,
        3 => DisplayFinalizationPhase::Retired,
        4 => DisplayFinalizationPhase::ReleasedCurrent,
        5 => DisplayFinalizationPhase::NativeReleaseReserved,
        _ => return Err("original finalization phase is unsupported".into()),
    };
    let terminal = if phase == DisplayFinalizationPhase::Protected {
        if !terminal.is_empty() {
            return Err("protected finalization has unexpected terminal data".into());
        }
        None
    } else {
        let terminal = crate::NativeDisplayFinalizationReservation::decode(terminal)?;
        terminal.validate_restoration(&record)?;
        Some(
            DisplayFinalizationReservationFacts::new(
                terminal.material().into(),
                terminal.binding().transaction_id.clone(),
                terminal.binding().effect_digest.to_hex(),
                terminal.binding().dispatch_digest.to_hex(),
            )
            .map_err(|e| e.to_string())?,
        )
    };
    DisplayOriginalFinalizationFacts::new(
        scope.clone(),
        material.original_checkpoint().into(),
        record.binding().transaction_id.clone(),
        record.binding().effect_digest.to_hex(),
        record.binding().dispatch_digest.to_hex(),
        phase,
        terminal,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    // Decoder fixtures only. No live Root, admission or native release proof.
    use super::*;
    use linura_core::{DisplayFinalizationMaterial, DisplayRestorationMaterial, RequestId};
    use linura_provider_sdk::{ComponentDigest, ExecutionBinding};
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn restoration() -> crate::NativeDisplayRestorationReservation {
        let material =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let effect = value(linura_provider_sdk::display_restoration_effect(material));
        let binding = value(ExecutionBinding::new(
            // Canonical UID/request transaction vector shared with the native reader.
            "transaction:v1:ae393480ff2a701ad2b95c237c1fea76adcf9b866471d3550847c6eff3f519a4",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        value(crate::NativeDisplayRestorationReservation::new(
            material, &binding,
        ))
    }
    fn terminal(
        record: &crate::NativeDisplayRestorationReservation,
        text: &str,
    ) -> crate::NativeDisplayFinalizationReservation {
        terminal_context(
            text,
            "restore-before-finalization",
            &record.binding().dispatch_digest.to_hex(),
        )
    }
    fn terminal_context(
        text: &str,
        request: &str,
        dispatch: &str,
    ) -> crate::NativeDisplayFinalizationReservation {
        let old = value(DisplayRestorationMaterial::decode(text));
        let material = value(DisplayFinalizationMaterial::encode(
            &value(RequestId::new(request)),
            dispatch,
            &"3".repeat(64),
            &"4".repeat(64),
            29,
            old.replacement().lock(),
            text,
        ));
        let effect = value(linura_provider_sdk::display_finalization_effect(&material));
        let binding = value(ExecutionBinding::new(
            "transaction:root-state-terminal",
            0,
            1,
            ComponentDigest::from_bytes([5; 32]),
            ComponentDigest::from_bytes([6; 32]),
            &effect,
        ));
        value(crate::NativeDisplayFinalizationReservation::new(
            &material, &binding,
        ))
    }
    #[test]
    fn root_state_decoder_requires_complete_purpose_separated_immutable_records() {
        let record = restoration();
        let scope = value(value(record.decoded_material()).recovery_scope());
        let bytes = record.canonical_bytes();
        let held = value(finalization_facts(&scope, &bytes, 0, &[]));
        assert_eq!(
            held.restoration_dispatch(),
            record.binding().dispatch_digest.to_hex()
        );
        assert_eq!(
            held.restoration_effect(),
            record.binding().effect_digest.to_hex()
        );
        assert_eq!(
            held.restoration_transaction(),
            record.binding().transaction_id
        );
        assert!(held.terminal().is_none());
        let terminal = terminal(&record, record.material());
        for (phase, expected) in [
            (1, linura_observation::DisplayFinalizationPhase::Reserved),
            (2, linura_observation::DisplayFinalizationPhase::Quiesced),
            (3, linura_observation::DisplayFinalizationPhase::Retired),
            (
                5,
                linura_observation::DisplayFinalizationPhase::NativeReleaseReserved,
            ),
            (
                4,
                linura_observation::DisplayFinalizationPhase::ReleasedCurrent,
            ),
        ] {
            let facts = value(finalization_facts(
                &scope,
                &bytes,
                phase,
                &terminal.canonical_bytes(),
            ));
            assert_eq!(facts.phase(), expected);
            assert_eq!(
                facts.terminal().map(|v| v.material()),
                Some(terminal.material())
            );
        }
        for length in 0..bytes.len() {
            assert!(finalization_facts(&scope, &bytes[..length], 0, &[]).is_err());
        }
        assert!(finalization_facts(&scope, &bytes, 0, &terminal.canonical_bytes()).is_err());
        assert!(finalization_facts(&scope, &bytes, 1, &[]).is_err());
        assert!(finalization_facts(&scope, &bytes, 4, &bytes).is_err());
        assert!(finalization_facts(&scope, &bytes, u32::MAX, &[]).is_err());
        let other = value(DisplayRecoveryScope::new(
            &"e".repeat(64),
            scope.replacement().clone(),
        ));
        assert!(finalization_facts(&other, &bytes, 0, &[]).is_err());
    }
    #[test]
    fn root_state_cannot_mix_different_full_restoration_material_with_equal_scope_and_dispatch() {
        let record = restoration();
        let old = value(record.decoded_material());
        let scope = value(old.recovery_scope());
        let substituted =
            record
                .material()
                .replacen(old.replacement_baseline_guard(), &"f".repeat(64), 1);
        assert_ne!(substituted, record.material());
        let changed = terminal(&record, &substituted);
        // Both individual codecs are valid; the joined immutable lineage is not.
        value(crate::NativeDisplayFinalizationReservation::decode(
            &changed.canonical_bytes(),
        ));
        assert!(
            finalization_facts(
                &scope,
                &record.canonical_bytes(),
                1,
                &changed.canonical_bytes()
            )
            .is_err()
        );
    }
    #[test]
    fn root_state_requires_actual_parent_dispatch_and_canonical_request_transaction() {
        let record = restoration();
        let scope = value(value(record.decoded_material()).recovery_scope());
        for (request, dispatch) in [
            ("another-request", record.binding().dispatch_digest.to_hex()),
            ("restore-before-finalization", "f".repeat(64)),
        ] {
            let terminal = terminal_context(record.material(), request, &dispatch);
            assert!(
                finalization_facts(
                    &scope,
                    &record.canonical_bytes(),
                    1,
                    &terminal.canonical_bytes()
                )
                .is_err()
            );
        }
    }
}
