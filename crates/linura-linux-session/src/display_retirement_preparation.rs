//! Exact one-use Root retirement-preparation comparison material. These bytes
//! are NOT a release credential, signed authority, native acknowledgement or
//! substitute for Control's durable committed history or live Root witnesses.
use linura_provider_sdk::ComponentDigest;
use crate::{
    MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION, NativeDisplayFinalizationReservation,
};

const DOMAIN: &[u8] = b"linura.native-display.retirement-preparation.v1";
pub const MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION: usize =
    MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION + 512;

pub struct NativeDisplayRetirementPreparation {
    terminal: NativeDisplayFinalizationReservation,
    control_state_version: u64,
    control_binding: ComponentDigest,
    control_observation: ComponentDigest,
}

impl std::fmt::Debug for NativeDisplayRetirementPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDisplayRetirementPreparation")
            .field("terminal_transaction", &self.terminal.binding().transaction_id)
            .field("control_state_version", &self.control_state_version)
            .finish_non_exhaustive()
    }
}

fn invalid() -> String {
    "native display retirement preparation is inconsistent or unavailable".into()
}

impl NativeDisplayRetirementPreparation {
    pub fn new(
        terminal: &NativeDisplayFinalizationReservation,
        control_state_version: u64,
        control_binding: ComponentDigest,
        control_observation: ComponentDigest,
    ) -> Result<Self, String> {
        if control_state_version == 0
            || control_binding == ComponentDigest::from_bytes([0; 32])
            || control_observation == ComponentDigest::from_bytes([0; 32])
        {
            return Err(invalid());
        }
        // A checked reconstruction prevents caller-created aggregates from
        // silently substituting the terminal's immutable effect or binding.
        let terminal = NativeDisplayFinalizationReservation::decode(&terminal.canonical_bytes())?;
        let result = Self {
            terminal,
            control_state_version,
            control_binding,
            control_observation,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION {
            return Err(invalid());
        }
        Ok(result)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION {
            return Err(invalid());
        }
        let mut remaining = bytes;
        let mut parts = Vec::with_capacity(5);
        for maximum in [
            DOMAIN.len(),
            20,
            64,
            64,
            MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION,
        ] {
            let (size, body) = remaining.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            if size > maximum {
                return Err(invalid());
            }
            let (field, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
            parts.push(field);
            remaining = tail;
        }
        if !remaining.is_empty() || parts[0] != DOMAIN {
            return Err(invalid());
        }
        let version = std::str::from_utf8(parts[1])
            .map_err(|_| invalid())?
            .parse::<u64>()
            .map_err(|_| invalid())?;
        if version.to_string().as_bytes() != parts[1] {
            return Err(invalid());
        }
        let digest = |raw: &[u8]| {
            let hex = std::str::from_utf8(raw).map_err(|_| invalid())?;
            let parsed = ComponentDigest::parse_hex(hex).map_err(|_| invalid())?;
            if parsed.to_hex() != hex {
                return Err(invalid());
            }
            Ok(parsed)
        };
        let terminal = NativeDisplayFinalizationReservation::decode(parts[4])?;
        let parsed = Self::new(&terminal, version, digest(parts[2])?, digest(parts[3])?)?;
        if parsed.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(parsed)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let terminal = self.terminal.canonical_bytes();
        let version = self.control_state_version.to_string();
        let binding = self.control_binding.to_hex();
        let observation = self.control_observation.to_hex();
        let mut encoded = Vec::new();
        for part in [
            DOMAIN,
            version.as_bytes(),
            binding.as_bytes(),
            observation.as_bytes(),
            terminal.as_slice(),
        ] {
            encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    /// Correlation only. The caller must still prove continuously held live
    /// Root/physical state, matching durable Control history and policy.
    #[must_use]
    pub const fn terminal(&self) -> &NativeDisplayFinalizationReservation {
        &self.terminal
    }
    #[must_use]
    pub const fn control_state_version(&self) -> u64 {
        self.control_state_version
    }
    #[must_use]
    pub const fn control_binding(&self) -> &ComponentDigest {
        &self.control_binding
    }
    #[must_use]
    pub const fn control_observation(&self) -> &ComponentDigest {
        &self.control_observation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{DisplayFinalizationMaterial, DisplayRestorationMaterial, RequestId};
    use linura_provider_sdk::{ExecutionBinding, display_finalization_effect};

    fn valid<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn preparation() -> NativeDisplayRetirementPreparation {
        let restored = include_str!(
            "../../linura-core/src/display_recovery/fixtures/original-baseline.txt"
        )
        .trim_end();
        let restoration = valid(DisplayRestorationMaterial::decode(restored));
        let material = valid(DisplayFinalizationMaterial::encode(
            &valid(RequestId::new("request:retirement-comparison")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            29,
            restoration.replacement().lock(),
            restored,
        ));
        let effect = valid(display_finalization_effect(&material));
        let binding = valid(ExecutionBinding::new(
            "transaction:retirement-comparison",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        let terminal = valid(NativeDisplayFinalizationReservation::new(&material, &binding));
        valid(NativeDisplayRetirementPreparation::new(
            &terminal,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        ))
    }

    #[test]
    fn canonical_retirement_preparation_is_bounded_and_not_a_terminal_grant() {
        let record = preparation();
        let bytes = record.canonical_bytes();
        let decoded = valid(NativeDisplayRetirementPreparation::decode(&bytes));
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert_eq!(decoded.control_state_version(), 7);
        assert_eq!(decoded.control_binding(), &ComponentDigest::from_bytes([3; 32]));
        assert_eq!(decoded.control_observation(), &ComponentDigest::from_bytes([4; 32]));
        assert_eq!(decoded.terminal().canonical_bytes(), record.terminal().canonical_bytes());
        assert!(NativeDisplayFinalizationReservation::decode(&bytes).is_err());
        for at in 0..bytes.len() {
            assert!(NativeDisplayRetirementPreparation::decode(&bytes[..at]).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(NativeDisplayRetirementPreparation::decode(&extended).is_err());
        let mut overflow = bytes.clone();
        overflow[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(NativeDisplayRetirementPreparation::decode(&overflow).is_err());
        assert!(NativeDisplayRetirementPreparation::decode(&vec![
            0u8;
            MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION + 1
        ])
        .is_err());
    }

    #[test]
    fn changed_anchor_or_trailing_material_refuses_without_release() {
        let record = preparation();
        for (version, binding, observation) in [
            (0, ComponentDigest::from_bytes([3; 32]), ComponentDigest::from_bytes([4; 32])),
            (7, ComponentDigest::from_bytes([0; 32]), ComponentDigest::from_bytes([4; 32])),
            (7, ComponentDigest::from_bytes([3; 32]), ComponentDigest::from_bytes([0; 32])),
        ] {
            assert!(
                NativeDisplayRetirementPreparation::new(record.terminal(), version, binding, observation)
                    .is_err()
            );
        }
        let bytes = record.canonical_bytes();
        let mut changed = bytes.clone();
        let pos = changed.len() - 1;
        changed[pos] ^= 1;
        assert!(NativeDisplayRetirementPreparation::decode(&changed).is_err());
    }
}
