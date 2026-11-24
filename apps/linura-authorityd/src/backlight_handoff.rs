//! Inactive, Control-owned admission for a future protected backlight handoff.
//!
//! Only a real `AuthorizedEffect` from Control can be admitted into the
//! production boundary. The SDK `ExecutionBinding` is correlation material,
//! NOT permission; the validator here is independently testable but cannot
//! issue a native worker grant. An admitted object cannot be cloned,
//! serialized or converted into `QualifiedBacklightAttempt`.
//!
//! A protected original-session supervisor, externally qualified device
//! generation and safe floor remain mandatory before any live effect.

use linura_control::AuthorizedEffect;
use linura_control::backlight_contract::{BacklightContractError, ProposedBacklightChange};
use linura_core::{BacklightResourceId, SessionLockId};
use linura_linux_session::NativeSessionChannel;
use linura_provider_sdk::{EffectDescriptor, ExecutionBinding};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightHandoffError {
    UnqualifiedBounds,
    InvalidEffect,
    WrongResource,
    InvalidDispatchBinding,
    WrongOriginalSession,
    WorkerUnavailable,
}

#[derive(Debug)]
/// Reviewable admission metadata only. Not an executable dispatch authority.
/// Construction requires the sealed, durably handed-off Control effect.
pub struct BacklightAuthorizedHandoff {
    effect: EffectDescriptor,
    binding: ExecutionBinding,
    target: BacklightResourceId,
    native_value: u32,
}

fn require_original_worker_scope(
    worker_lock: &SessionLockId,
    resource: &BacklightResourceId,
) -> Result<(), BacklightHandoffError> {
    if worker_lock.epoch() != resource.epoch() {
        return Err(BacklightHandoffError::WrongOriginalSession);
    }
    Ok(())
}

impl BacklightAuthorizedHandoff {
    /// The protected-supervisor-bound admission entry point. An authenticated
    /// per-UID security supervisor and the graphical login it observes must
    /// match the canonical lock before the already-durably-consumed effect can
    /// be projected into native metadata. This alone cannot prove the separate
    /// native SetBrightness caller's actual logind session membership.
    ///
    /// This is NOT a physical grant: no qualified brightness writer, worker
    /// handoff transport or executor request can be produced from this object.
    /// A failed worker observation leaves the original durable dispatch
    /// reservation uncertain; it NEVER authorizes a second reservation.
    pub fn from_control_with_protected_owner(
        authorized: AuthorizedEffect,
        expected: &BacklightResourceId,
        worker_lock: &SessionLockId,
        control_bus: &NativeSessionChannel,
        qualified_minimum: u32,
        maximum: u32,
    ) -> Result<Self, BacklightHandoffError> {
        require_original_worker_scope(worker_lock, expected)?;
        control_bus
            .observe_backlight_owner(worker_lock)
            .map_err(|_| BacklightHandoffError::WorkerUnavailable)?;
        Self::from_control(authorized, expected, qualified_minimum, maximum)
    }

    /// This is the only admission from the sealed Control effect: the genuine
    /// `DispatchPermit` has already been durably consumed by Control. This
    /// object is NOT itself a bearer credential and is not exposed on IPC.
    /// There is deliberately no caller of this function until the protected
    /// supervisor and hardware qualification gates are implemented.
    fn from_control(
        authorized: AuthorizedEffect,
        expected: &BacklightResourceId,
        qualified_minimum: u32,
        maximum: u32,
    ) -> Result<Self, BacklightHandoffError> {
        let (effect, binding) = authorized.into_executor_request();
        let native_value =
            validate_handoff_parts(&effect, &binding, expected, qualified_minimum, maximum)?;
        Ok(Self {
            effect,
            binding,
            target: expected.clone(),
            native_value,
        })
    }

    /// Reviewable fields only. No mechanism for minting a physical device
    /// generation or protected worker dispatch is present.
    pub fn effect(&self) -> &EffectDescriptor {
        &self.effect
    }

    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    pub fn target(&self) -> &BacklightResourceId {
        &self.target
    }

    pub fn native_value(&self) -> u32 {
        self.native_value
    }
}

fn validate_handoff_parts(
    effect: &EffectDescriptor,
    binding: &ExecutionBinding,
    expected: &BacklightResourceId,
    qualified_minimum: u32,
    maximum: u32,
) -> Result<u32, BacklightHandoffError> {
    // A caller cannot replace the physical qualification with a zero floor,
    // overflow value, or malformed provider payload.
    let change = ProposedBacklightChange::from_effect(effect, qualified_minimum, maximum).map_err(
        |error| match error {
            BacklightContractError::UnqualifiedMinimum => BacklightHandoffError::UnqualifiedBounds,
            _ => BacklightHandoffError::InvalidEffect,
        },
    )?;
    if change.target() != expected {
        return Err(BacklightHandoffError::WrongResource);
    }
    // This authenticates the *integrity of correlation fields only*.
    // Admission authority comes from consuming AuthorizedEffect above.
    binding
        .validate_for(effect)
        .map_err(|_| BacklightHandoffError::InvalidDispatchBinding)?;
    Ok(change.native_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BacklightDeviceGeneration, BootId, SessionEpoch};
    use linura_provider_sdk::ComponentDigest;

    fn resource(device: &str) -> BacklightResourceId {
        let epoch = SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
            1000,
            "c2",
            42,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        BacklightResourceId::new(
            epoch,
            BacklightDeviceGeneration::new(device).unwrap_or_else(|e| unreachable!("{e}")),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn fixture() -> (BacklightResourceId, EffectDescriptor, ExecutionBinding) {
        let target = resource("98765432-1234-4567-89ab-0123456789ab");
        let effect = ProposedBacklightChange::new(target.clone(), "50", 20, 100)
            .unwrap_or_else(|e| unreachable!("{e:?}"))
            .effect_descriptor()
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        let digest = ComponentDigest::parse_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let binding = ExecutionBinding::new(
            "transaction:v1:original-user-backlight-test",
            1,
            2,
            digest,
            digest,
            &effect,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        (target, effect, binding)
    }

    #[test]
    fn exact_effect_and_dispatch_correlation_validate_as_data_only() {
        let (target, effect, binding) = fixture();
        assert_eq!(
            validate_handoff_parts(&effect, &binding, &target, 20, 100),
            Ok(50)
        );
        // This does NOT create a real AuthorizedEffect or an executable grant.
    }

    #[test]
    fn same_uid_and_session_cannot_substitute_a_different_device_generation() {
        let (target, effect, binding) = fixture();
        let substituted = resource("98765432-1234-4567-89ab-0123456789ac");
        assert_ne!(target, substituted);
        assert_eq!(
            validate_handoff_parts(&effect, &binding, &substituted, 20, 100),
            Err(BacklightHandoffError::WrongResource)
        );
    }

    #[test]
    fn worker_session_must_match_the_exact_original_effect_user_and_epoch() {
        use linura_core::{SecurityOwnerInvocationId, SessionLockId};

        let target = resource("98765432-1234-4567-89ab-0123456789ab");
        let invocation = SecurityOwnerInvocationId::new("12345678-1234-4567-89ab-0123456789ab")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let correct = SessionLockId::new(target.epoch().clone(), invocation.clone(), 1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(require_original_worker_scope(&correct, &target), Ok(()));

        let other_epoch = SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|error| unreachable!("{error}")),
            1001,
            "c2",
            42,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let wrong_user = SessionLockId::new(other_epoch, invocation, 1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            require_original_worker_scope(&wrong_user, &target),
            Err(BacklightHandoffError::WrongOriginalSession)
        );
    }

    #[test]
    fn zero_or_invalid_floor_does_not_turn_correlation_into_qualification() {
        let (target, effect, binding) = fixture();
        for (minimum, maximum) in [(0, 100), (101, 100), (20, 0)] {
            assert_eq!(
                validate_handoff_parts(&effect, &binding, &target, minimum, maximum),
                Err(BacklightHandoffError::UnqualifiedBounds)
            );
        }
    }

    #[test]
    fn changed_target_method_extra_key_or_provider_are_denied() {
        let (target, effect, binding) = fixture();
        let mut changed = effect.clone();
        changed.operation = "write-sysfs".into();
        assert_eq!(
            validate_handoff_parts(&changed, &binding, &target, 20, 100),
            Err(BacklightHandoffError::InvalidEffect)
        );
        let mut changed = effect.clone();
        changed
            .canonical_payload
            .extend_from_slice(b"subsystem=leds\n");
        assert_eq!(
            validate_handoff_parts(&changed, &binding, &target, 20, 100),
            Err(BacklightHandoffError::InvalidEffect)
        );
        let mut changed = effect.clone();
        changed.provider = linura_core::ProviderId::new("untrusted-backlight")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            validate_handoff_parts(&changed, &binding, &target, 20, 100),
            Err(BacklightHandoffError::InvalidEffect)
        );
    }

    #[test]
    fn cloned_and_forged_correlation_material_never_passes_integrity_review() {
        let (target, effect, binding) = fixture();
        let mut changed = binding.clone();
        changed.generation += 1;
        assert_eq!(
            validate_handoff_parts(&effect, &changed, &target, 20, 100),
            Err(BacklightHandoffError::InvalidDispatchBinding)
        );
        let mut changed = binding.clone();
        changed.state_version += 1;
        assert_eq!(
            validate_handoff_parts(&effect, &changed, &target, 20, 100),
            Err(BacklightHandoffError::InvalidDispatchBinding)
        );
        let mut changed = binding.clone();
        changed.transaction_id.push_str("-replayed");
        assert_eq!(
            validate_handoff_parts(&effect, &changed, &target, 20, 100),
            Err(BacklightHandoffError::InvalidDispatchBinding)
        );
        let mut changed = binding.clone();
        changed.authority_use_digest = effect.digest();
        assert_eq!(
            validate_handoff_parts(&effect, &changed, &target, 20, 100),
            Err(BacklightHandoffError::InvalidDispatchBinding)
        );
    }
}
