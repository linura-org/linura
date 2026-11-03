//! Bounded private comparison material for a fresh restoration reservation.
//! Neither these bytes nor a validated execution binding authorizes an effect.
//! The supervised executor must receive Control's prepared one-use handoff;
//! the original Guard independently admits its caller and retained witnesses.
use linura_core::DisplayRestorationMaterial;
use linura_provider_sdk::{ComponentDigest, ExecutionBinding, display_restoration_effect};

const DOMAIN: &str = "linura.native-display.restoration-reservation.v1";
pub const MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION: usize = 16 * 1024;

pub struct NativeDisplayRestorationReservation {
    binding: ExecutionBinding,
    material: String,
}
impl std::fmt::Debug for NativeDisplayRestorationReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDisplayRestorationReservation")
            .field("material_bytes", &self.material.len())
            .finish_non_exhaustive()
    }
}
fn invalid() -> String {
    "native display restoration reservation is inconsistent or unsupported".into()
}
impl NativeDisplayRestorationReservation {
    pub fn new(material: &str, binding: &ExecutionBinding) -> Result<Self, String> {
        let effect = display_restoration_effect(material)?;
        binding.validate_for(&effect).map_err(|_| invalid())?;
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
        let reservation = Self {
            binding: binding.clone(),
            material: material.into(),
        };
        if reservation.canonical_bytes().len() > MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION {
            return Err(invalid());
        }
        Ok(reservation)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION {
            return Err(invalid());
        }
        let mut rest = bytes;
        let mut fields = Vec::with_capacity(9);
        for _ in 0..9 {
            let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
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
    pub fn decoded_material(&self) -> Result<DisplayRestorationMaterial<'_>, String> {
        DisplayRestorationMaterial::decode(&self.material).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests;
