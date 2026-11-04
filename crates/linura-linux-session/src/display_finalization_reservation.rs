//! Narrow terminal-reservation comparison codec. It admits no caller, releases
//! no protection and cannot replace Control's freshly prepared sealed handoff.
use linura_core::{DisplayFinalizationMaterial, MAX_DISPLAY_FINALIZATION_BYTES};
use linura_provider_sdk::{ComponentDigest, ExecutionBinding, display_finalization_effect};

const DOMAIN: &str = "linura.native-display.finalization-reservation.v1";
pub const MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION: usize = 16 * 1024;

pub struct NativeDisplayFinalizationReservation {
    binding: ExecutionBinding,
    material: String,
}
impl std::fmt::Debug for NativeDisplayFinalizationReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDisplayFinalizationReservation")
            .field("material_bytes", &self.material.len())
            .finish_non_exhaustive()
    }
}
fn invalid() -> String {
    "native display finalization reservation is inconsistent or unsupported".into()
}
impl NativeDisplayFinalizationReservation {
    pub fn new(material: &str, binding: &ExecutionBinding) -> Result<Self, String> {
        let effect = display_finalization_effect(material)?;
        binding.validate_for(&effect).map_err(|_| invalid())?;
        let decoded = DisplayFinalizationMaterial::decode(material).map_err(|_| invalid())?;
        if decoded.restoration_dispatch() == binding.dispatch_digest.to_hex() {
            return Err(invalid());
        }
        for digest in [
            binding.authority_binding_digest,
            binding.authority_use_digest,
            binding.effect_digest,
            binding.dispatch_digest,
        ] {
            if digest == ComponentDigest::from_bytes([0; 32]) {
                return Err(invalid());
            }
        }
        let record = Self {
            binding: binding.clone(),
            material: material.into(),
        };
        if record.canonical_bytes().len() > MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION {
            return Err(invalid());
        }
        Ok(record)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION {
            return Err(invalid());
        }
        let mut rest = bytes;
        let mut fields = Vec::with_capacity(9);
        for maximum in [
            DOMAIN.len(),
            256,
            20,
            20,
            64,
            64,
            64,
            64,
            MAX_DISPLAY_FINALIZATION_BYTES,
        ] {
            let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            if size > maximum {
                return Err(invalid());
            }
            let (field, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
            fields.push(std::str::from_utf8(field).map_err(|_| invalid())?);
            rest = tail;
        }
        if !rest.is_empty() || fields[0] != DOMAIN {
            return Err(invalid());
        }
        let number = |text: &str| {
            let number: u64 = text.parse().map_err(|_| invalid())?;
            if number.to_string() != text {
                return Err(invalid());
            }
            Ok(number)
        };
        let digest = |text: &str| {
            let digest = ComponentDigest::parse_hex(text).map_err(|_| invalid())?;
            if digest.to_hex() != text {
                return Err(invalid());
            }
            Ok(digest)
        };
        let binding = ExecutionBinding {
            transaction_id: fields[1].into(),
            generation: number(fields[2])?,
            state_version: number(fields[3])?,
            authority_binding_digest: digest(fields[4])?,
            authority_use_digest: digest(fields[5])?,
            effect_digest: digest(fields[6])?,
            dispatch_digest: digest(fields[7])?,
        };
        let record = Self::new(fields[8], &binding)?;
        if record.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(record)
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for field in [
            DOMAIN,
            &self.binding.transaction_id,
            &self.binding.generation.to_string(),
            &self.binding.state_version.to_string(),
            &self.binding.authority_binding_digest.to_hex(),
            &self.binding.authority_use_digest.to_hex(),
            &self.binding.effect_digest.to_hex(),
            &self.binding.dispatch_digest.to_hex(),
            &self.material,
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    }
    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    pub fn decoded_material(&self) -> Result<DisplayFinalizationMaterial<'_>, String> {
        DisplayFinalizationMaterial::decode(&self.material).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn fixture() -> NativeDisplayFinalizationReservation {
        let old =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let restored = value(linura_core::DisplayRestorationMaterial::decode(old));
        let material = value(DisplayFinalizationMaterial::encode(
            &value(linura_core::RequestId::new("request:terminal-fixture")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            29,
            restored.replacement().lock(),
            old,
        ));
        let effect = value(display_finalization_effect(&material));
        let binding = value(ExecutionBinding::new(
            "transaction:terminal-fixture",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        value(NativeDisplayFinalizationReservation::new(
            &material, &binding,
        ))
    }
    #[test]
    fn terminal_reservation_is_canonical_bounded_and_never_an_old_restoration_record() {
        let record = fixture();
        let bytes = record.canonical_bytes();
        let decoded = value(NativeDisplayFinalizationReservation::decode(&bytes));
        assert_eq!(decoded.binding(), record.binding());
        assert_eq!(decoded.material(), record.material());
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert!(crate::NativeDisplayRestorationReservation::decode(&bytes).is_err());
        assert!(!format!("{record:?}").contains("LNRF:"));
        for end in 0..bytes.len() {
            assert!(NativeDisplayFinalizationReservation::decode(&bytes[..end]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(NativeDisplayFinalizationReservation::decode(&extra).is_err());
        assert!(
            NativeDisplayFinalizationReservation::decode(&vec![
                0;
                MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION
                    + 1
            ])
            .is_err()
        );
        let mut length = bytes.clone();
        length[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(NativeDisplayFinalizationReservation::decode(&length).is_err());
    }
    #[test]
    fn changed_binding_material_and_nonterminal_authority_are_rejected() {
        let record = fixture();
        for index in 0..7 {
            let mut binding = record.binding().clone();
            match index {
                0 => binding.transaction_id.push_str("-other"),
                1 => binding.generation += 1,
                2 => binding.state_version += 1,
                3 => binding.authority_binding_digest = ComponentDigest::from_bytes([3; 32]),
                4 => binding.authority_use_digest = ComponentDigest::from_bytes([3; 32]),
                5 => binding.effect_digest = ComponentDigest::from_bytes([3; 32]),
                _ => binding.dispatch_digest = ComponentDigest::from_bytes([3; 32]),
            }
            assert!(
                NativeDisplayFinalizationReservation::new(record.material(), &binding).is_err()
            );
        }
        let old = value(record.decoded_material())
            .restoration_text()
            .to_owned();
        let restoration = value(linura_provider_sdk::display_restoration_effect(&old));
        let binding = value(ExecutionBinding::new(
            "transaction:old-restoration",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &restoration,
        ));
        assert!(NativeDisplayFinalizationReservation::new(record.material(), &binding).is_err());
        assert!(NativeDisplayFinalizationReservation::new(&old, record.binding()).is_err());
        let changed = record
            .material()
            .replacen(&"3".repeat(64), &"4".repeat(64), 1);
        assert!(NativeDisplayFinalizationReservation::new(&changed, record.binding()).is_err());
    }
}
