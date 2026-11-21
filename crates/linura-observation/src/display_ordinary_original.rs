//! Fresh original Root/kernel/power continuity for an ordinary same-invocation
//! terminal. Historical comparison is not a release grant or current scanout.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{DisplayLayoutMaterial, DisplayOrdinaryReleaseScope};
use std::collections::BTreeMap;
pub const DISPLAY_ORDINARY_ORIGINAL_CAPABILITY: &str = "display.ordinary-original.observe";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryOriginalComparison {
    pub material: String,
    pub transaction: String,
    pub checkpoint: String,
    pub native_guard: String,
    pub integration: String,
    pub sampled_boot_ms: u64,
    pub original_deadline_unix_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryOriginalFacts {
    scope: DisplayOrdinaryReleaseScope,
    comparison: DisplayOrdinaryOriginalComparison,
}
impl DisplayOrdinaryOriginalFacts {
    pub fn new(
        scope: DisplayOrdinaryReleaseScope,
        comparison: DisplayOrdinaryOriginalComparison,
    ) -> Result<Self, DisplayEvidenceError> {
        let material = DisplayLayoutMaterial::decode(&comparison.material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        if material.topology() != scope.topology() {
            return Err(DisplayEvidenceError::Identity);
        }
        if [
            &comparison.checkpoint,
            &comparison.native_guard,
            &comparison.integration,
        ]
        .iter()
        .any(|v| !canonical_digest(v))
            || !comparison.transaction.starts_with("transaction:")
            || comparison.transaction.len() <= 12
            || comparison.transaction.len() > 256
            || !comparison
                .transaction
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-'))
            || comparison.sampled_boot_ms == 0
            || comparison.original_deadline_unix_ms == 0
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self { scope, comparison })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let c = &self.comparison;
        BTreeMap::from([
            ("ordinary_original_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            (
                "original_material".into(),
                ObservedValue::Text(c.material.clone()),
            ),
            (
                "original_transaction".into(),
                ObservedValue::Text(c.transaction.clone()),
            ),
            (
                "checkpoint_digest".into(),
                ObservedValue::Text(c.checkpoint.clone()),
            ),
            (
                "native_guard".into(),
                ObservedValue::Text(c.native_guard.clone()),
            ),
            (
                "integration_digest".into(),
                ObservedValue::Text(c.integration.clone()),
            ),
            (
                "original_sampled_boot_ms".into(),
                ObservedValue::U64(c.sampled_boot_ms),
            ),
            (
                "original_deadline_unix_ms".into(),
                ObservedValue::U64(c.original_deadline_unix_ms),
            ),
            ("root_power_held".into(), ObservedValue::Bool(true)),
        ])
    }
    pub fn from_envelope(
        sample: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if sample.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || sample.capability.as_str() != DISPLAY_ORDINARY_ORIGINAL_CAPABILITY
            || sample.authority != ObservationAuthority::NativeApi
            || sample.sequence == 0
            || sample.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if sample.observed_at_unix_ms == 0
            || sample.valid_for_ms == 0
            || sample.valid_for_ms > 2000
            || now
                .checked_sub(sample.observed_at_unix_ms)
                .is_none_or(|age| age >= sample.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let a = &sample.attributes;
        if a.len() != 10
            || number(a, "ordinary_original_schema")? != 1
            || text(a, "original_dispatch")? != scope.original_dispatch()
            || !boolean(a, "root_power_held")?
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let result = Self::new(
            scope.clone(),
            DisplayOrdinaryOriginalComparison {
                material: text(a, "original_material")?.into(),
                transaction: text(a, "original_transaction")?.into(),
                checkpoint: text(a, "checkpoint_digest")?.into(),
                native_guard: text(a, "native_guard")?.into(),
                integration: text(a, "integration_digest")?.into(),
                sampled_boot_ms: number(a, "original_sampled_boot_ms")?,
                original_deadline_unix_ms: number(a, "original_deadline_unix_ms")?,
            },
        )?;
        if result.attributes() != *a {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }
    #[must_use]
    pub const fn scope(&self) -> &DisplayOrdinaryReleaseScope {
        &self.scope
    }
    #[must_use]
    pub const fn comparison(&self) -> &DisplayOrdinaryOriginalComparison {
        &self.comparison
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayRestorationMaterial, ProviderId};
    fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
        v.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn same_invocation_root_continuity_never_aliases_recovery_or_releases_anything() {
        let text =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let old = value(DisplayRestorationMaterial::decode(text));
        let start = text.find("LNDI:1;").unwrap_or_else(|| unreachable!());
        let length: usize = text[..start]
            .rsplit(';')
            .next()
            .and_then(|s| s.strip_suffix(':'))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| unreachable!());
        let scope = value(DisplayOrdinaryReleaseScope::new(
            old.original_dispatch(),
            old.original().topology().clone(),
        ));
        let facts = value(DisplayOrdinaryOriginalFacts::new(
            scope.clone(),
            DisplayOrdinaryOriginalComparison {
                material: text[start..start + length].into(),
                transaction: "transaction:ordinary-original".into(),
                checkpoint: "1".repeat(64),
                native_guard: "2".repeat(64),
                integration: "3".repeat(64),
                sampled_boot_ms: 10,
                original_deadline_unix_ms: 100,
            },
        ));
        // Expired historical confirmation is not refreshed; only current Root
        // continuity gets the envelope's fresh, independent two-second window.
        let sample = ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(DISPLAY_ORDINARY_ORIGINAL_CAPABILITY)),
            resource: value(scope.resource_id()),
            authority: ObservationAuthority::NativeApi,
            sequence: 1,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            attributes: facts.attributes(),
        };
        assert_eq!(
            value(DisplayOrdinaryOriginalFacts::from_envelope(
                &sample, &scope, 1001
            )),
            facts
        );
        for fault in 0..13 {
            let mut changed = sample.clone();
            match fault {
                0 => changed.authority = ObservationAuthority::SyntheticTest,
                1 => changed.provider = value(ProviderId::new("attacker")),
                2 => {
                    changed.capability = value(CapabilityId::new(
                        crate::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
                    ))
                }
                3 => changed.sequence = 0,
                4 => changed.valid_for_ms = 2001,
                5 => {
                    changed
                        .attributes
                        .insert("root_power_held".into(), ObservedValue::Bool(false));
                }
                6 => {
                    changed.attributes.insert(
                        "checkpoint_digest".into(),
                        ObservedValue::Text("0".repeat(64)),
                    );
                }
                7 => {
                    changed.attributes.insert(
                        "original_transaction".into(),
                        ObservedValue::Text("committed".into()),
                    );
                }
                8 => {
                    changed
                        .attributes
                        .insert("original_sampled_boot_ms".into(), ObservedValue::U64(0));
                }
                9 => {
                    changed.attributes.insert(
                        "original_material".into(),
                        ObservedValue::Text(facts.comparison.material.replace(":1000:", ":1001:")),
                    );
                }
                10 => {
                    changed
                        .attributes
                        .insert("ordinary_original_schema".into(), ObservedValue::U64(2));
                }
                11 => {
                    changed.attributes.remove("integration_digest");
                }
                _ => {
                    changed
                        .attributes
                        .insert("released".into(), ObservedValue::Bool(true));
                }
            }
            assert!(
                DisplayOrdinaryOriginalFacts::from_envelope(&changed, &scope, 1001).is_err(),
                "fault {fault}"
            );
        }
        for now in [0, 999, 3000, u64::MAX] {
            assert!(DisplayOrdinaryOriginalFacts::from_envelope(&sample, &scope, now).is_err());
        }
        let foreign = value(DisplayOrdinaryReleaseScope::new(
            old.original_dispatch(),
            old.replacement().topology().clone(),
        ));
        assert!(DisplayOrdinaryOriginalFacts::new(foreign, facts.comparison.clone()).is_err());
        assert!(
            crate::DisplayOriginalProtectionFacts::from_envelope(
                &sample,
                &value(old.recovery_scope()),
                1001
            )
            .is_err()
        );
    }
}
