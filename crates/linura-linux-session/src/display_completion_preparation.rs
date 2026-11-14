//! Bounded comparison material for the separately authorized current-lifetime
//! transfer. Bytes alone grant no authority and cannot reconstruct live peers.
use std::collections::BTreeMap;

use linura_core::DisplayOutputId;
use linura_observation::{
    DisplayNativeHandoffFacts, DisplayNativeHandoffLineage, DisplayNativeHandoffOutput,
    DisplayNativeHandoffWindow,
};
use linura_provider_sdk::ComponentDigest;

use crate::{NativeDisplayRestorationReservation, NativeDisplayRetirementPreparation};

pub(crate) mod current_commit;
pub(crate) mod final_retirement;
pub(crate) mod power;
pub(crate) mod root_retirement;

const DOMAIN: &[u8] = b"linura.native-display.completion-preparation.v1";
pub const MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION: usize =
    crate::MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION + 8 * 1024;

#[derive(Debug)]
pub struct NativeDisplayCompletionPreparation {
    parent: NativeDisplayRetirementPreparation,
    preparation: ComponentDigest,
    verification: ComponentDigest,
    expires_at_unix_ms: u64,
    frames: DisplayNativeHandoffFacts,
}

fn invalid() -> String {
    "native display completion preparation is inconsistent or unavailable".into()
}

pub(super) fn field<'a>(rest: &mut &'a [u8], bound: usize) -> Result<&'a [u8], String> {
    let (size, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())?;
    if size == 0 || size > bound {
        return Err(invalid());
    }
    let (value, tail) = tail.split_at_checked(size).ok_or_else(invalid)?;
    *rest = tail;
    Ok(value)
}
pub(super) fn text<'a>(rest: &mut &'a [u8], bound: usize) -> Result<&'a str, String> {
    std::str::from_utf8(field(rest, bound)?).map_err(|_| invalid())
}
pub(super) fn number(rest: &mut &[u8]) -> Result<u64, String> {
    let raw = text(rest, 20)?;
    let value = raw.parse::<u64>().map_err(|_| invalid())?;
    if value.to_string() != raw {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn digest(rest: &mut &[u8]) -> Result<ComponentDigest, String> {
    let raw = text(rest, 64)?;
    let parsed = ComponentDigest::parse_hex(raw).map_err(|_| invalid())?;
    if parsed.to_hex() != raw || parsed == ComponentDigest::from_bytes([0; 32]) {
        return Err(invalid());
    }
    Ok(parsed)
}
pub(super) fn append(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

impl NativeDisplayCompletionPreparation {
    pub fn new(
        parent: &NativeDisplayRetirementPreparation,
        preparation: ComponentDigest,
        verification: ComponentDigest,
        frames: &DisplayNativeHandoffFacts,
        expires_at_unix_ms: u64,
    ) -> Result<Self, String> {
        let parent = NativeDisplayRetirementPreparation::decode(&parent.canonical_bytes())?;
        let material = parent.terminal().decoded_material()?;
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let binding = parent.terminal().binding();
        let lineage = frames.lineage();
        if preparation == ComponentDigest::from_bytes([0; 32])
            || verification == ComponentDigest::from_bytes([0; 32])
            || preparation == verification
            || expires_at_unix_ms <= frames.window().observed_unix_ms
            || expires_at_unix_ms > frames.window().deadline_unix_ms
            || lineage.checkpoint != material.restoration().original_checkpoint()
            || lineage.restoration_dispatch != material.restoration_dispatch()
            || lineage.terminal_transaction != binding.transaction_id
            || lineage.terminal_effect != binding.effect_digest.to_hex()
            || lineage.terminal_dispatch != binding.dispatch_digest.to_hex()
            || lineage.terminal_link != material.terminal_link()
            || lineage.source_guard != material.restored_source_guard()
            || lineage.post_write_epoch != material.post_write_epoch()
            || frames.outputs().len()
                != material
                    .restoration()
                    .mapping()
                    .replacement()
                    .outputs()
                    .len()
            || material
                .restoration()
                .mapping()
                .replacement()
                .outputs()
                .iter()
                .any(|id| !frames.outputs().contains_key(id))
            || frames
                .outputs()
                .keys()
                .any(|id| id.topology() != scope.replacement())
        {
            return Err(invalid());
        }
        // Validate the complete typed inventory without manufacturing a native
        // ObservationEnvelope or treating the comparison bytes as current truth.
        let frames = DisplayNativeHandoffFacts::new(
            scope,
            lineage.clone(),
            frames.window(),
            frames.outputs().clone(),
        )
        .map_err(|_| invalid())?;
        let result = Self {
            parent,
            preparation,
            verification,
            expires_at_unix_ms,
            frames,
        };
        if result.canonical_bytes().len() > MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION {
            return Err(invalid());
        }
        Ok(result)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION {
            return Err(invalid());
        }
        let mut rest = bytes;
        if field(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(invalid());
        }
        let parent = NativeDisplayRetirementPreparation::decode(field(
            &mut rest,
            crate::MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION,
        )?)?;
        let preparation = digest(&mut rest)?;
        let verification = digest(&mut rest)?;
        let restoration_transaction = text(&mut rest, 256)?.to_owned();
        let restoration_effect = digest(&mut rest)?.to_hex();
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&mut rest)?,
            observed_boot_ms: number(&mut rest)?,
            deadline_unix_ms: number(&mut rest)?,
            deadline_boot_ms: number(&mut rest)?,
        };
        let security_epoch = number(&mut rest)?;
        let expires_at_unix_ms = number(&mut rest)?;
        let count = number(&mut rest)?;
        if !(1..=16).contains(&count) {
            return Err(invalid());
        }
        let material = parent.terminal().decoded_material()?;
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let binding = parent.terminal().binding();
        let lineage = DisplayNativeHandoffLineage {
            checkpoint: material.restoration().original_checkpoint().into(),
            restoration_transaction,
            restoration_effect,
            restoration_dispatch: material.restoration_dispatch().into(),
            terminal_transaction: binding.transaction_id.clone(),
            terminal_effect: binding.effect_digest.to_hex(),
            terminal_dispatch: binding.dispatch_digest.to_hex(),
            terminal_link: material.terminal_link().into(),
            source_guard: material.restored_source_guard().into(),
            post_write_epoch: material.post_write_epoch(),
            security_epoch,
        };
        let mut outputs = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let output = DisplayOutputId::new(
                scope.replacement().clone(),
                number(&mut rest)?,
                number(&mut rest)?,
            )
            .map_err(|_| invalid())?;
            if previous.as_ref().is_some_and(|old| old >= &output) {
                return Err(invalid());
            }
            previous = Some(output.clone());
            let enabled = match number(&mut rest)? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            let mut kms = [0_u32; 4];
            for value in &mut kms {
                *value = u32::try_from(number(&mut rest)?).map_err(|_| invalid())?;
            }
            let row = DisplayNativeHandoffOutput {
                enabled,
                connector: kms[0],
                crtc: kms[1],
                plane: kms[2],
                framebuffer: kms[3],
                spend_high_water: number(&mut rest)?,
                completed_commit: number(&mut rest)?,
            };
            if outputs.insert(output, row).is_some() {
                return Err(invalid());
            }
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        let frames = DisplayNativeHandoffFacts::new(scope, lineage, window, outputs)
            .map_err(|_| invalid())?;
        let result = Self::new(
            &parent,
            preparation,
            verification,
            &frames,
            expires_at_unix_ms,
        )?;
        if result.canonical_bytes() != bytes {
            return Err(invalid());
        }
        Ok(result)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [
            DOMAIN,
            &self.parent.canonical_bytes(),
            self.preparation.to_hex().as_bytes(),
            self.verification.to_hex().as_bytes(),
            self.frames.lineage().restoration_transaction.as_bytes(),
            self.frames.lineage().restoration_effect.as_bytes(),
        ] {
            append(&mut out, value);
        }
        let window = self.frames.window();
        for value in [
            window.observed_unix_ms,
            window.observed_boot_ms,
            window.deadline_unix_ms,
            window.deadline_boot_ms,
            self.frames.lineage().security_epoch,
            self.expires_at_unix_ms,
            self.frames.outputs().len() as u64,
        ] {
            append(&mut out, value.to_string().as_bytes());
        }
        for (id, row) in self.frames.outputs() {
            for value in [
                id.handle(),
                id.generation(),
                u64::from(row.enabled),
                u64::from(row.connector),
                u64::from(row.crtc),
                u64::from(row.plane),
                u64::from(row.framebuffer),
                row.spend_high_water,
                row.completed_commit,
            ] {
                append(&mut out, value.to_string().as_bytes());
            }
        }
        out
    }

    pub fn validate_restoration(
        &self,
        retained: &NativeDisplayRestorationReservation,
    ) -> Result<(), String> {
        self.parent.terminal().validate_restoration(retained)?;
        if self.frames.lineage().restoration_transaction != retained.binding().transaction_id
            || self.frames.lineage().restoration_effect != retained.binding().effect_digest.to_hex()
        {
            return Err(invalid());
        }
        Ok(())
    }
    #[must_use]
    pub const fn parent(&self) -> &NativeDisplayRetirementPreparation {
        &self.parent
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayNativeHandoffFacts {
        &self.frames
    }
    #[must_use]
    pub const fn preparation_digest(&self) -> &ComponentDigest {
        &self.preparation
    }
    #[must_use]
    pub const fn verification_digest(&self) -> &ComponentDigest {
        &self.verification
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[cfg(test)]
mod tests {
    // Comparison fixtures only, never independent physical evidence.
    use super::*;
    use crate::NativeDisplayFinalizationReservation;
    use linura_provider_sdk::{ExecutionBinding, display_finalization_effect};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn fixture() -> NativeDisplayCompletionPreparation {
        let material = include_str!(
            "../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
        )
        .trim_end();
        let effect = value(display_finalization_effect(material));
        let binding = value(ExecutionBinding::new(
            "transaction:completion-codec",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        let terminal = value(NativeDisplayFinalizationReservation::new(
            material, &binding,
        ));
        let parent = value(NativeDisplayRetirementPreparation::new(
            &terminal,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        ));
        let decoded = value(terminal.decoded_material());
        let scope = value(decoded.recovery_scope());
        let lineage = DisplayNativeHandoffLineage {
            checkpoint: decoded.restoration().original_checkpoint().into(),
            restoration_transaction: "transaction:restoration-codec".into(),
            restoration_effect: "a".repeat(64),
            restoration_dispatch: decoded.restoration_dispatch().into(),
            terminal_transaction: binding.transaction_id.clone(),
            terminal_effect: binding.effect_digest.to_hex(),
            terminal_dispatch: binding.dispatch_digest.to_hex(),
            terminal_link: decoded.terminal_link().into(),
            source_guard: decoded.restored_source_guard().into(),
            post_write_epoch: decoded.post_write_epoch(),
            security_epoch: 13,
        };
        let outputs = decoded
            .restoration()
            .mapping()
            .replacement()
            .outputs()
            .iter()
            .enumerate()
            .map(|(i, id)| {
                (
                    id.clone(),
                    DisplayNativeHandoffOutput {
                        enabled: true,
                        connector: u32::try_from(i + 1).unwrap_or_else(|_| unreachable!()),
                        crtc: u32::try_from(i + 11).unwrap_or_else(|_| unreachable!()),
                        plane: u32::try_from(i + 21).unwrap_or_else(|_| unreachable!()),
                        framebuffer: u32::try_from(i + 31).unwrap_or_else(|_| unreachable!()),
                        spend_high_water: 5,
                        completed_commit: 6,
                    },
                )
            })
            .collect();
        let frames = value(DisplayNativeHandoffFacts::new(
            scope,
            lineage,
            DisplayNativeHandoffWindow {
                observed_unix_ms: 1001,
                observed_boot_ms: 101,
                deadline_unix_ms: 1200,
                deadline_boot_ms: 300,
            },
            outputs,
        ));
        value(NativeDisplayCompletionPreparation::new(
            &parent,
            ComponentDigest::from_bytes([5; 32]),
            ComponentDigest::from_bytes([6; 32]),
            &frames,
            1150,
        ))
    }
    fn parts(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut rest = bytes;
        let mut parts = Vec::new();
        while !rest.is_empty() {
            parts.push(value(field(&mut rest, MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION)).to_vec());
        }
        parts
    }
    fn encoded(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in parts {
            append(&mut bytes, part);
        }
        bytes
    }
    #[test]
    fn completion_comparison_preserves_exact_parent_clocks_and_every_output() {
        let record = fixture();
        let bytes = record.canonical_bytes();
        let decoded = value(NativeDisplayCompletionPreparation::decode(&bytes));
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert_eq!(decoded.frames(), record.frames());
        assert_eq!(decoded.expires_at_unix_ms(), 1150);
        assert!(NativeDisplayRetirementPreparation::decode(&bytes).is_err());
        assert!(NativeDisplayFinalizationReservation::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(NativeDisplayCompletionPreparation::decode(&bytes[..end]).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(NativeDisplayCompletionPreparation::decode(&extended).is_err());
        let mut overflow = bytes.clone();
        overflow[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(NativeDisplayCompletionPreparation::decode(&overflow).is_err());
        assert!(
            NativeDisplayCompletionPreparation::decode(&vec![
                0;
                MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION
                    + 1
            ])
            .is_err()
        );
    }
    #[test]
    fn noncanonical_or_incomplete_completion_material_cannot_become_a_root_record() {
        let record = fixture();
        let original = parts(&record.canonical_bytes());
        for (index, replacement) in [
            (0, b"foreign-purpose".as_slice()),
            (1, b"foreign-parent"),
            (
                2,
                b"0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (3, original[2].as_slice()),
            (4, b"bad-transaction"),
            (
                5,
                b"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            ),
            (6, b"01001"),
            (7, b"0"),
            (8, b"1001"),
            (9, b"101"),
            (10, b"0"),
            (11, b"1001"),
            (11, b"1201"),
            (12, b"0"),
            (12, b"17"),
            (13, b"0"),
            (14, b"0"),
            (15, b"2"),
            (16, b"4294967296"),
            (20, b"6"),
            (21, b"5"),
        ] {
            let mut changed = original.clone();
            changed[index] = replacement.to_vec();
            assert!(
                NativeDisplayCompletionPreparation::decode(&encoded(&changed)).is_err(),
                "field {index}"
            );
        }
        if record.frames().outputs().len() > 1 {
            let mut missing = original.clone();
            missing[12] = b"1".to_vec();
            missing.truncate(22);
            assert!(NativeDisplayCompletionPreparation::decode(&encoded(&missing)).is_err());
            let mut duplicate = original.clone();
            duplicate[22..31].clone_from_slice(&original[13..22]);
            assert!(NativeDisplayCompletionPreparation::decode(&encoded(&duplicate)).is_err());
            let mut unsorted = original.clone();
            for index in 0..9 {
                unsorted.swap(13 + index, 22 + index);
            }
            assert!(NativeDisplayCompletionPreparation::decode(&encoded(&unsorted)).is_err());
        }
    }
    #[test]
    fn power_preparation_binds_original_parent_complete_current_inventory_and_both_clocks() {
        use linura_observation::{DisplayNativeCurrentFacts, DisplayNativeCurrentOutput};
        use power::{
            MAX_NATIVE_DISPLAY_POWER_RETIREMENT, NativeDisplayPowerRetirementPreparation as Power,
        };
        use sha2::{Digest, Sha256};
        let parent = fixture();
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: 1100,
            observed_boot_ms: 200,
            deadline_unix_ms: 1400,
            deadline_boot_ms: 250,
        };
        let frames = value(DisplayNativeCurrentFacts::new(
            parent.frames().scope().clone(),
            parent.frames().lineage().clone(),
            window,
            parent
                .frames()
                .outputs()
                .iter()
                .map(|(id, row)| {
                    (
                        id.clone(),
                        DisplayNativeCurrentOutput {
                            enabled: row.enabled,
                            connector: row.connector,
                            crtc: row.crtc,
                            plane: row.plane,
                            framebuffer: row.framebuffer,
                            handoff_commit: row.completed_commit,
                            completed_commit: row.completed_commit + 1,
                        },
                    )
                })
                .collect(),
            ComponentDigest::from_bytes(Sha256::digest(parent.canonical_bytes()).into()).to_hex(),
            true,
            true,
            None,
            None,
        ));
        let make = |frames: &DisplayNativeCurrentFacts, expiry| {
            Power::new(
                &parent,
                ComponentDigest::from_bytes([7; 32]),
                ComponentDigest::from_bytes([8; 32]),
                frames,
                expiry,
            )
        };
        let record = value(make(&frames, 1149));
        let bytes = record.canonical_bytes();
        assert_eq!(value(Power::decode(&bytes)).canonical_bytes(), bytes);
        assert!(NativeDisplayCompletionPreparation::decode(&bytes).is_err());
        assert!(Power::decode(&parent.canonical_bytes()).is_err());
        for length in 0..bytes.len() {
            assert!(Power::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Power::decode(&trailing).is_err());
        assert!(Power::decode(&vec![0; MAX_NATIVE_DISPLAY_POWER_RETIREMENT + 1]).is_err());
        assert!(make(&frames, 1100).is_err());
        assert!(make(&frames, 1151).is_err()); // tighter BOOTTIME, not wall-only
        let original = parts(&bytes);
        for (index, bad) in [
            (0, b"wrong".as_slice()),
            (1, b"wrong-parent"),
            (2, b"0"),
            (3, original[2].as_slice()),
            (4, b"1151"),
            (5, b"01100"),
            (9, b"0"),
            (12, b"2"),
            (13, b"4294967296"),
            (17, b"0"),
            (18, b"0"),
        ] {
            let mut changed = original.clone();
            changed[index] = bad.to_vec();
            assert!(Power::decode(&encoded(&changed)).is_err(), "field {index}");
        }
        let absent = value(DisplayNativeCurrentFacts::new(
            frames.scope().clone(),
            frames.lineage().clone(),
            window,
            frames.outputs().clone(),
            frames.completion_digest().into(),
            true,
            false,
            None,
            None,
        ));
        let root = value(
            root_retirement::NativeDisplayRootRetirementPreparation::new(
                &record,
                ComponentDigest::from_bytes([9; 32]),
                ComponentDigest::from_bytes([10; 32]),
                &absent,
                1149,
            ),
        );
        let root_bytes = root.canonical_bytes();
        assert_eq!(
            value(root_retirement::NativeDisplayRootRetirementPreparation::decode(&root_bytes))
                .canonical_bytes(),
            root_bytes
        );
        assert!(Power::decode(&root_bytes).is_err());
        assert!(
            root_retirement::NativeDisplayRootRetirementPreparation::new(
                &record,
                ComponentDigest::from_bytes([9; 32]),
                ComponentDigest::from_bytes([10; 32]),
                &frames,
                1149
            )
            .is_err()
        );
        for end in 0..root_bytes.len() {
            assert!(
                root_retirement::NativeDisplayRootRetirementPreparation::decode(&root_bytes[..end])
                    .is_err()
            );
        }
        let mut wrong = root_bytes.clone();
        wrong.push(0);
        assert!(root_retirement::NativeDisplayRootRetirementPreparation::decode(&wrong).is_err());
        assert!(
            root_retirement::NativeDisplayRootRetirementPreparation::new(
                &record,
                ComponentDigest::from_bytes([9; 32]),
                ComponentDigest::from_bytes([10; 32]),
                &absent,
                1151
            )
            .is_err()
        );
        let binding = *root.parent().parent().parent().control_binding();
        let committed = value(current_commit::NativeDisplayCurrentCommitPreparation::new(
            &root,
            ComponentDigest::from_bytes([11; 32]),
            ComponentDigest::from_bytes([12; 32]),
            0,
            9,
            binding,
            &absent,
            1149,
        ));
        let committed_bytes = committed.canonical_bytes();
        assert_eq!(
            value(current_commit::NativeDisplayCurrentCommitPreparation::decode(&committed_bytes))
                .canonical_bytes(),
            committed_bytes
        );
        assert_eq!(committed.control_version(), 9);
        for end in 0..committed_bytes.len() {
            assert!(
                current_commit::NativeDisplayCurrentCommitPreparation::decode(
                    &committed_bytes[..end]
                )
                .is_err()
            );
        }
        assert!(
            root_retirement::NativeDisplayRootRetirementPreparation::decode(&committed_bytes)
                .is_err()
        );
        for (generation, version, binding) in [
            (1, 9, binding),
            (0, 8, binding),
            (0, 10, binding),
            (0, 9, ComponentDigest::from_bytes([1; 32])),
        ] {
            assert!(
                current_commit::NativeDisplayCurrentCommitPreparation::new(
                    &root,
                    ComponentDigest::from_bytes([11; 32]),
                    ComponentDigest::from_bytes([12; 32]),
                    generation,
                    version,
                    binding,
                    &absent,
                    1149
                )
                .is_err()
            );
        }
        let qualified = value(DisplayNativeCurrentFacts::new(
            absent.scope().clone(),
            absent.lineage().clone(),
            window,
            absent.outputs().clone(),
            absent.completion_digest().into(),
            true,
            false,
            Some(committed.record_digest().to_hex()),
            None,
        ));
        assert!(qualified.follows_current_qualification(&absent));
        assert!(!qualified.reconciles(&absent));
        let final_record = value(
            final_retirement::NativeDisplayFinalRetirementPreparation::new(
                &committed,
                ComponentDigest::from_bytes([13; 32]),
                ComponentDigest::from_bytes([14; 32]),
                &qualified,
                1149,
            ),
        );
        let final_bytes = final_record.canonical_bytes();
        assert_eq!(
            value(final_retirement::NativeDisplayFinalRetirementPreparation::decode(&final_bytes))
                .canonical_bytes(),
            final_bytes
        );
        assert!(
            current_commit::NativeDisplayCurrentCommitPreparation::decode(&final_bytes).is_err()
        );
        assert!(
            final_retirement::NativeDisplayFinalRetirementPreparation::new(
                &committed,
                ComponentDigest::from_bytes([13; 32]),
                ComponentDigest::from_bytes([14; 32]),
                &absent,
                1149,
            )
            .is_err()
        );
        let foreign = value(DisplayNativeCurrentFacts::new(
            absent.scope().clone(),
            absent.lineage().clone(),
            window,
            absent.outputs().clone(),
            absent.completion_digest().into(),
            true,
            false,
            Some("1".repeat(64)),
            None,
        ));
        assert!(
            final_retirement::NativeDisplayFinalRetirementPreparation::new(
                &committed,
                ComponentDigest::from_bytes([13; 32]),
                ComponentDigest::from_bytes([14; 32]),
                &foreign,
                1149,
            )
            .is_err()
        );
        for end in 0..final_bytes.len() {
            assert!(
                final_retirement::NativeDisplayFinalRetirementPreparation::decode(
                    &final_bytes[..end]
                )
                .is_err()
            );
        }
        let mut trailing = final_bytes.clone();
        trailing.push(0);
        assert!(
            final_retirement::NativeDisplayFinalRetirementPreparation::decode(&trailing).is_err()
        );
        let original = parts(&final_bytes);
        for (index, bad) in [
            (0, b"wrong-purpose".as_slice()),
            (1, root_bytes.as_slice()),
            (2, b"0"),
            (3, original[2].as_slice()),
            (4, b"1151"),
            (5, b"01100"),
            (9, b"0"),
            (10, b"9"),
            (13, b"4294967296"),
            (18, b"0"),
        ] {
            let mut changed = original.clone();
            changed[index] = bad.to_vec();
            assert!(
                final_retirement::NativeDisplayFinalRetirementPreparation::decode(&encoded(
                    &changed
                ))
                .is_err(),
                "final field {index}"
            );
        }
        for (input, power) in [(false, true), (true, false)] {
            let wrong = value(DisplayNativeCurrentFacts::new(
                frames.scope().clone(),
                frames.lineage().clone(),
                window,
                frames.outputs().clone(),
                frames.completion_digest().into(),
                input,
                power,
                None,
                None,
            ));
            assert!(make(&wrong, 1149).is_err());
        }
    }
}
