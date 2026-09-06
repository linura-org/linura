use std::fmt::{Debug, Formatter};
use std::time::Duration;

use linura_control::{
    AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier,
    MANAGED_SYSTEMD_CAPABILITY, MANAGED_SYSTEMD_OPERATION, MANAGED_SYSTEMD_PROVIDER,
};
use linura_core::CapabilityId;
use linura_executor_systemd::{
    INTERFACE_NAME as EXECUTOR_INTERFACE, ManagedActiveState, ManagedUnitName,
    OBJECT_PATH as EXECUTOR_OBJECT, SERVICE_NAME as EXECUTOR_SERVICE, managed_active_state_effect,
};
use linura_linux_observation::SystemdObserver;
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionDisposition, ExecutionOutcome,
    IndependentVerifier as _, Observer as _, VerificationOutcome,
};
use linura_verifier_systemd::{SystemdActiveStateExpectation, SystemdActiveStateVerifier};

type ExecutorOutcomeWire = (String, String, String);
const SYSTEMD_SETTLE_ATTEMPTS: usize = 50;
const SYSTEMD_SETTLE_INTERVAL_MS: u64 = 100;
const SYSTEMD_SETTLE_INTERVAL: Duration = Duration::from_millis(SYSTEMD_SETTLE_INTERVAL_MS);
const _: () = assert!(SYSTEMD_SETTLE_ATTEMPTS > 1 && SYSTEMD_SETTLE_ATTEMPTS <= 64);
const _: () = assert!(SYSTEMD_SETTLE_INTERVAL_MS > 0 && SYSTEMD_SETTLE_INTERVAL_MS <= 250);

pub(crate) struct SystemdExecutorClient {
    connection: zbus::blocking::Connection,
}

impl Debug for SystemdExecutorClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemdExecutorClient")
            .finish_non_exhaustive()
    }
}

impl SystemdExecutorClient {
    pub(crate) fn connect() -> Result<Self, String> {
        zbus::blocking::Connection::system()
            .map(|connection| Self { connection })
            .map_err(|error| format!("cannot connect to system bus for executor handoff: {error}"))
    }
}

impl AuthorizedEffectExecutor for SystemdExecutorClient {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String> {
        let (effect, binding) = authorization.into_executor_request();
        let (unit, state) = parse_managed_effect(&effect)?;
        let proxy = zbus::blocking::Proxy::new(
            &self.connection,
            EXECUTOR_SERVICE,
            EXECUTOR_OBJECT,
            EXECUTOR_INTERFACE,
        )
        .map_err(|error| format!("cannot bind managed executor proxy: {error}"))?;

        let wire: ExecutorOutcomeWire = proxy
            .call(
                "SetManagedActiveState",
                &(
                    unit.as_str(),
                    state.as_str(),
                    binding.transaction_id.as_str(),
                    binding.generation,
                    binding.state_version,
                    binding.authority_binding_digest.to_hex(),
                    binding.authority_use_digest.to_hex(),
                    binding.effect_digest.to_hex(),
                    binding.dispatch_digest.to_hex(),
                ),
            )
            .map_err(|error| format!("managed executor transport failed: {error}"))?;

        let disposition = match wire.0.as_str() {
            "rejected-before-dispatch" => ExecutionDisposition::RejectedBeforeDispatch,
            "dispatched" => ExecutionDisposition::Dispatched,
            "indeterminate" => ExecutionDisposition::Indeterminate,
            value => return Err(format!("executor returned unknown disposition {value:?}")),
        };
        let dispatch_digest = if wire.1.is_empty()
            && disposition == ExecutionDisposition::RejectedBeforeDispatch
        {
            binding.dispatch_digest
        } else {
            ComponentDigest::parse_hex(&wire.1)
                .map_err(|error| format!("executor returned malformed dispatch digest: {error}"))?
        };
        if dispatch_digest != binding.dispatch_digest {
            return Err("executor response substituted the authorized dispatch digest".into());
        }
        ExecutionOutcome::new(disposition, dispatch_digest, wire.2)
            .map_err(|error| format!("executor returned invalid outcome: {error}"))
    }
}

pub(crate) struct FreshSystemdVerifier {
    observer: SystemdObserver,
    verifier: SystemdActiveStateVerifier,
}

impl Debug for FreshSystemdVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreshSystemdVerifier")
            .finish_non_exhaustive()
    }
}

impl FreshSystemdVerifier {
    pub(crate) fn connect() -> Result<Self, String> {
        Ok(Self {
            observer: SystemdObserver::connect()
                .map_err(|error| format!("cannot connect independent systemd observer: {error}"))?,
            verifier: SystemdActiveStateVerifier,
        })
    }
}

impl IndependentManagedVerifier for FreshSystemdVerifier {
    fn verify_effect(&mut self, effect: &EffectDescriptor) -> Result<VerificationOutcome, String> {
        let (unit, state) = parse_managed_effect(effect)?;
        let expectation = SystemdActiveStateExpectation::new(unit.as_str(), state.as_str())
            .map_err(|error| error.to_string())?;
        let capability =
            CapabilityId::new(MANAGED_SYSTEMD_CAPABILITY).map_err(|error| error.to_string())?;
        let observation = self
            .observer
            .observe_authoritative(&effect.resource, &capability)
            .map_err(|error| format!("independent systemd observation failed: {error}"))?;
        Ok(self.verifier.verify(&expectation, &observation))
    }

    fn post_dispatch_settle_attempts(&self) -> usize {
        SYSTEMD_SETTLE_ATTEMPTS
    }

    fn post_dispatch_settle_interval(&self) -> Duration {
        SYSTEMD_SETTLE_INTERVAL
    }
}

pub(crate) fn parse_managed_effect(
    effect: &EffectDescriptor,
) -> Result<(ManagedUnitName, ManagedActiveState), String> {
    if effect.provider.as_str() != MANAGED_SYSTEMD_PROVIDER
        || effect.operation != MANAGED_SYSTEMD_OPERATION
    {
        return Err("effect is outside the v0.6 managed systemd contract".into());
    }
    let payload = std::str::from_utf8(&effect.canonical_payload)
        .map_err(|_| "managed effect payload is not UTF-8".to_owned())?;
    let mut lines = payload.lines();
    let unit = lines
        .next()
        .and_then(|line| line.strip_prefix("unit="))
        .ok_or_else(|| "managed effect is missing canonical unit".to_owned())?;
    let state = lines
        .next()
        .and_then(|line| line.strip_prefix("active_state="))
        .ok_or_else(|| "managed effect is missing canonical active state".to_owned())?;
    if lines.next().is_some() || !payload.ends_with('\n') {
        return Err("managed effect payload has trailing or non-canonical material".into());
    }
    let unit = ManagedUnitName::parse(unit).map_err(|error| error.to_string())?;
    let state = ManagedActiveState::parse(state).map_err(str::to_owned)?;
    let canonical = managed_active_state_effect(&unit, state).map_err(|error| error.to_string())?;
    if canonical != *effect {
        return Err("managed effect differs from the executor canonical encoding".into());
    }
    Ok((unit, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_only_executor_canonical_effect() {
        let unit = ManagedUnitName::parse("linura-managed-example.service")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let effect = managed_active_state_effect(&unit, ManagedActiveState::Active)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let (parsed_unit, parsed_state) =
            parse_managed_effect(&effect).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(parsed_unit, unit);
        assert_eq!(parsed_state, ManagedActiveState::Active);
    }
}
