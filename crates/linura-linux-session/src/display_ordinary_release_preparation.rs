//! Closed ordinary-release comparison on its own canonical managed binding.
//! These bytes are not a Root/native grant and cannot reconstruct approval.
use linura_core::{DisplayOrdinaryReleaseMaterial, MAX_DISPLAY_ORDINARY_RELEASE_BYTES};
use linura_observation::DisplayNativeHandoffWindow;
use linura_provider_sdk::{ComponentDigest, ExecutionBinding, display_ordinary_release_effect};
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"linura.native-display.ordinary-release.v1";
pub const MAX_NATIVE_DISPLAY_ORDINARY_RELEASE: usize = MAX_DISPLAY_ORDINARY_RELEASE_BYTES + 4096;
#[derive(Debug)]
pub struct NativeDisplayOrdinaryReleasePreparation {
    material: String,
    binding: ExecutionBinding,
    window: DisplayNativeHandoffWindow,
}
impl NativeDisplayOrdinaryReleasePreparation {
    pub fn new(
        material: &str,
        binding: &ExecutionBinding,
        window: DisplayNativeHandoffWindow,
    ) -> Result<Self, String> {
        if material.len() > MAX_DISPLAY_ORDINARY_RELEASE_BYTES {
            return Err(invalid());
        }
        DisplayOrdinaryReleaseMaterial::decode(material).map_err(|_| invalid())?;
        if binding.transaction_id.len() > 256
            || [
                binding.authority_binding_digest,
                binding.authority_use_digest,
                binding.effect_digest,
                binding.dispatch_digest,
            ]
            .contains(&ComponentDigest::from_bytes([0; 32]))
        {
            return Err(invalid());
        }

        binding
            .validate_for(&display_ordinary_release_effect(material)?)
            .map_err(|_| invalid())?;
        window.valid_for_ms().map_err(|_| invalid())?;
        let result = Self {
            material: material.into(),
            binding: binding.clone(),
            window,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_ORDINARY_RELEASE {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_ORDINARY_RELEASE {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let material = std::str::from_utf8(field(&mut rest, MAX_DISPLAY_ORDINARY_RELEASE_BYTES)?)
            .map_err(|_| invalid())?;
        let binding = ExecutionBinding {
            transaction_id: std::str::from_utf8(field(&mut rest, 256)?)
                .map_err(|_| invalid())?
                .into(),
            generation: number(&mut rest)?,
            state_version: number(&mut rest)?,
            authority_binding_digest: digest(&mut rest)?,
            authority_use_digest: digest(&mut rest)?,
            effect_digest: digest(&mut rest)?,
            dispatch_digest: digest(&mut rest)?,
        };
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        if !rest.is_empty() {
            return Err(invalid());
        }
        let result = Self::new(material, &binding, window)?;
        if result.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for field in [
            DOMAIN,
            self.material.as_bytes(),
            self.binding.transaction_id.as_bytes(),
            self.binding.generation.to_string().as_bytes(),
            self.binding.state_version.to_string().as_bytes(),
            self.binding.authority_binding_digest.to_hex().as_bytes(),
            self.binding.authority_use_digest.to_hex().as_bytes(),
            self.binding.effect_digest.to_hex().as_bytes(),
            self.binding.dispatch_digest.to_hex().as_bytes(),
            self.window.observed_unix_ms.to_string().as_bytes(),
            self.window.observed_boot_ms.to_string().as_bytes(),
            self.window.deadline_unix_ms.to_string().as_bytes(),
            self.window.deadline_boot_ms.to_string().as_bytes(),
        ] {
            result.extend_from_slice(&(field.len() as u64).to_be_bytes());
            result.extend_from_slice(field);
        }
        result
    }
    pub fn material(&self) -> &str {
        &self.material
    }
    pub fn decoded_material(&self) -> Result<DisplayOrdinaryReleaseMaterial<'_>, String> {
        DisplayOrdinaryReleaseMaterial::decode(&self.material).map_err(|_| invalid())
    }
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
    pub fn record_digest(&self) -> ComponentDigest {
        ComponentDigest::from_bytes(Sha256::digest(self.canonical_bytes()).into())
    }
}
fn invalid() -> String {
    "ordinary release comparison is malformed or unsupported; no authority".into()
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
fn number(rest: &mut &[u8]) -> Result<u64, String> {
    let raw = std::str::from_utf8(field(rest, 20)?).map_err(|_| invalid())?;
    let value = raw.parse::<u64>().map_err(|_| invalid())?;
    if value.to_string() != raw {
        return Err(invalid());
    }
    Ok(value)
}
fn digest(rest: &mut &[u8]) -> Result<ComponentDigest, String> {
    let raw = std::str::from_utf8(field(rest, 64)?).map_err(|_| invalid())?;
    let value = ComponentDigest::parse_hex(raw).map_err(|_| invalid())?;
    if value.to_hex() != raw || value == ComponentDigest::from_bytes([0; 32]) {
        return Err(invalid());
    }
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        DisplayOrdinaryReleaseLineage, DisplayOrdinaryReleaseOutcome, DisplayRestorationMaterial,
    };
    fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
        v.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn ordinary_preparation_keeps_its_own_binding_full_intent_and_both_producer_clocks() {
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
        let material = value(DisplayOrdinaryReleaseMaterial::encode(
            &DisplayOrdinaryReleaseLineage {
                original_request: old.original_request().clone(),
                original_dispatch: old.original_dispatch(),
                terminal_record: &"1".repeat(64),
                original_checkpoint: old.original_checkpoint(),
                signed_binding: &"2".repeat(64),
                generation: 0,
                state_version: 9,
                current_source_guard: &"3".repeat(64),
            },
            DisplayOrdinaryReleaseOutcome::Keep,
            old.original().lock(),
            &text[start..start + length],
        ));
        let effect = value(display_ordinary_release_effect(&material));
        let binding = value(ExecutionBinding::new(
            "transaction:ordinary-release",
            0,
            1,
            ComponentDigest::from_bytes([4; 32]),
            ComponentDigest::from_bytes([5; 32]),
            &effect,
        ));
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: 1000,
            observed_boot_ms: 100,
            deadline_unix_ms: 3000,
            deadline_boot_ms: 150,
        };
        let record = value(NativeDisplayOrdinaryReleasePreparation::new(
            &material, &binding, window,
        ));
        let bytes = record.canonical_bytes();
        let decoded = value(NativeDisplayOrdinaryReleasePreparation::decode(&bytes));
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert_eq!(decoded.window(), window);
        assert_eq!(decoded.binding(), &binding);
        assert_eq!(decoded.material(), material);
        assert_eq!(decoded.record_digest(), record.record_digest());
        assert_eq!(
            value(decoded.decoded_material()).outcome(),
            DisplayOrdinaryReleaseOutcome::Keep
        );
        for end in 0..bytes.len() {
            assert!(
                NativeDisplayOrdinaryReleasePreparation::decode(&bytes[..end]).is_err(),
                "truncated {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(NativeDisplayOrdinaryReleasePreparation::decode(&trailing).is_err());
        assert!(
            NativeDisplayOrdinaryReleasePreparation::decode(&vec![
                0;
                MAX_NATIVE_DISPLAY_ORDINARY_RELEASE
                    + 1
            ])
            .is_err()
        );
        for fault in 0..5 {
            let mut wrong = binding.clone();
            match fault {
                0 => wrong.effect_digest = ComponentDigest::from_bytes([6; 32]),
                1 => wrong.authority_use_digest = ComponentDigest::from_bytes([6; 32]),
                2 => wrong.generation += 1,
                3 => wrong.state_version += 1,
                _ => wrong.transaction_id = "transaction:foreign".into(),
            };
            assert!(
                NativeDisplayOrdinaryReleasePreparation::new(&material, &wrong, window).is_err()
            );
        }
        for zero_authority in [true, false] {
            let wrong = value(ExecutionBinding::new(
                "transaction:ordinary-release",
                0,
                1,
                ComponentDigest::from_bytes([if zero_authority { 0 } else { 4 }; 32]),
                ComponentDigest::from_bytes([if zero_authority { 5 } else { 0 }; 32]),
                &effect,
            ));
            assert!(
                NativeDisplayOrdinaryReleasePreparation::new(&material, &wrong, window).is_err()
            );
        }
        let apply = value(linura_provider_sdk::display_layout_effect(
            &text[start..start + length],
        ));
        let old_binding = value(ExecutionBinding::new(
            "transaction:ordinary-release",
            0,
            1,
            ComponentDigest::from_bytes([4; 32]),
            ComponentDigest::from_bytes([5; 32]),
            &apply,
        ));
        assert!(
            NativeDisplayOrdinaryReleasePreparation::new(&material, &old_binding, window).is_err()
        );
        for fault in 0..5 {
            let mut wrong = window;
            match fault {
                0 => wrong.observed_unix_ms = 0,
                1 => wrong.observed_boot_ms = 0,
                2 => wrong.deadline_unix_ms = 1000,
                3 => wrong.deadline_boot_ms = 2101,
                _ => wrong.deadline_unix_ms = 3001,
            };
            assert!(
                NativeDisplayOrdinaryReleasePreparation::new(&material, &binding, wrong).is_err()
            );
        }
        assert!(crate::NativeDisplayFinalizationReservation::decode(&bytes).is_err());
        assert!(crate::NativeDisplayCompletionPreparation::decode(&bytes).is_err());
    }
}
