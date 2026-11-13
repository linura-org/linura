//! Fresh fixed-service attestation for the narrow prepared handoff. Correlation
//! hashes alone are never permission to call the executor.
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use linura_core::{SessionLockId, SessionTransitionId};
use linura_provider_sdk::{
    ComponentDigest, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) sender: String,
    uid: u32,
    pub(crate) pid: u32,
    invocation: Vec<u8>,
}

type ExecStart = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

fn live_launch(role: NativeSessionRole, image: &str, pid: u32, launches: &[ExecStart]) -> bool {
    let arguments = match role {
        NativeSessionRole::DisplayProtection => vec![image, "--display-protection"],
        NativeSessionRole::Control | NativeSessionRole::Executor => vec![image],
    };
    matches!(launches, [(exe, argv, false, real, mono, 0, 0, launch_pid, 0, 0)]
        if exe == image && argv == &arguments && *real != 0 && *mono != 0 && *launch_pid == pid)
}

/// Fixed supervised pre-start helper only. The anonymous connection acquires
/// no executor/Control name and exposes no channel/effect handle to its caller.
/// Control independently authenticates this process and exact systemd program.
pub fn protect_before_native_sleep() -> Result<(), String> {
    // This is the fixed process entry mode, before any bus/runtime thread or
    // transport is created. The same-PID re-exec retains native supervision.
    crate::sleep_helper::enter_unprivileged()?;
    let channel = NativeSessionChannel {
        connection: crate::bus::connect_native_bus(None)?,
        role: NativeSessionRole::Executor,
    };
    let control = channel.trusted_service(NativeSessionRole::Control, Instant::now())?;
    let reply = channel.call_with_budget(
        &control.sender,
        "/org/linura/SleepGate1",
        "org.linura.SleepGate1",
        "ProtectBeforeSleep",
        &(),
        Duration::from_secs(35),
    )?;
    if reply
        .header()
        .sender()
        .is_none_or(|sender| sender.as_str() != control.sender)
    {
        return Err("native sleep gate reply has a different authenticated sender".into());
    }
    let (fenced,): (bool,) = reply
        .body()
        .deserialize()
        .map_err(|_| "native sleep gate reply is malformed")?;
    if !fenced || channel.trusted_service(NativeSessionRole::Control, Instant::now())? != control {
        return Err("native sleep coverage is not fenced by the same supervised Control".into());
    }
    Ok(())
}

impl NativeSessionChannel {
    pub(crate) fn observe_original_display_completion(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        use linura_observation::{DisplayCompletionLineage, DisplayOriginalCompletionFacts};
        use sha2::Digest;
        self.require_role(NativeSessionRole::Control)?;
        let invalid = || "original completion lifetime unavailable; no reconstruction".to_owned();
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err(invalid());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let began_wall = crate::owner::unix_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|_| invalid())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadCompletion",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION + 32
        {
            return Err(invalid());
        }
        let (bytes, phase): (Vec<u8>, u32) = reply.body().deserialize().map_err(|_| invalid())?;
        if phase != 2 {
            return Err(invalid());
        }
        let record = crate::NativeDisplayCompletionPreparation::decode(&bytes)?;
        let facts = DisplayOriginalCompletionFacts::new(
            DisplayCompletionLineage {
                record: ComponentDigest::from_bytes(sha2::Sha256::digest(&bytes).into()).to_hex(),
                preparation: record.preparation_digest().to_hex(),
                verification: record.verification_digest().to_hex(),
                material: record.parent().terminal().material().into(),
            },
            record.frames().clone(),
        )
        .map_err(|_| invalid())?;
        if facts.first().scope() != scope
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err(invalid());
        }
        let end_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        if began_boot == 0
            || began_wall == 0
            || end_boot
                .checked_sub(began_boot)
                .is_none_or(|age| age >= 2000)
            || now.checked_sub(began_wall).is_none_or(|age| age >= 2000)
            || started.elapsed() >= Duration::from_secs(2)
        {
            return Err(invalid());
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|_| invalid())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_COMPLETION_CAPABILITY,
            )
            .map_err(|_| invalid())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: began_wall,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        DisplayOriginalCompletionFacts::from_envelope(&observation, scope, now)
            .map_err(|_| invalid())?;
        Ok(observation)
    }

    pub(crate) fn observe_original_display_power_retirement(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        use linura_observation::DisplayOriginalPowerRetirementFacts;
        use sha2::Digest;
        self.require_role(NativeSessionRole::Control)?;
        let invalid = || "original completion lifetime unavailable; no reconstruction".to_owned();
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err(invalid());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let began_wall = crate::owner::unix_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|_| invalid())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadPowerRetirement",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ayu"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_POWER_RETIREMENT + 32
        {
            return Err(invalid());
        }
        let (bytes, phase): (Vec<u8>, u32) = reply.body().deserialize().map_err(|_| invalid())?;
        if !matches!(phase, 1 | 2) {
            return Err(invalid());
        }
        let record = crate::NativeDisplayPowerRetirementPreparation::decode(&bytes)?;
        let facts = DisplayOriginalPowerRetirementFacts::new(
            scope.clone(),
            ComponentDigest::from_bytes(sha2::Sha256::digest(&bytes).into()).to_hex(),
            ComponentDigest::from_bytes(
                sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
            )
            .to_hex(),
            record.preparation_digest().to_hex(),
            record.checkpoint_digest().to_hex(),
            phase == 2,
        )
        .map_err(|_| invalid())?;
        if record.parent().frames().scope() != scope
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err(invalid());
        }
        let end_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        if began_boot == 0
            || began_wall == 0
            || end_boot
                .checked_sub(began_boot)
                .is_none_or(|age| age >= 2000)
            || now.checked_sub(began_wall).is_none_or(|age| age >= 2000)
            || started.elapsed() >= Duration::from_secs(2)
        {
            return Err(invalid());
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|_| invalid())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY,
            )
            .map_err(|_| invalid())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: began_wall,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        DisplayOriginalPowerRetirementFacts::from_envelope(&observation, scope, now)
            .map_err(|_| invalid())?;
        Ok(observation)
    }

    pub(crate) fn observe_original_display_final_retirement(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        use linura_observation::DisplayOriginalFinalRetirementFacts;
        use sha2::Digest;
        self.require_role(NativeSessionRole::Control)?;
        let invalid = || "original completion lifetime unavailable; no reconstruction".to_owned();
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err(invalid());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let began_wall = crate::owner::unix_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|_| invalid())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadFinalRetirement",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ayuay"
            || reply.body().len() > 2 * crate::MAX_NATIVE_DISPLAY_FINAL_RETIREMENT + 1024
        {
            return Err(invalid());
        }
        let (bytes, phase, completed): (Vec<u8>, u32, Vec<u8>) =
            reply.body().deserialize().map_err(|_| invalid())?;
        if !matches!(phase, 1..=3) {
            return Err(invalid());
        }
        let record = crate::NativeDisplayFinalRetirementPreparation::decode(&bytes)?;
        let completed = if phase == 3 {
            let retained = crate::NativeDisplayReleasedCurrentRecord::decode(&completed)?;
            if retained.parent().canonical_bytes() != bytes {
                return Err(invalid());
            }
            Some(linura_observation::DisplayReleasedCurrentLineage {
                record: ComponentDigest::from_bytes(sha2::Sha256::digest(&completed).into())
                    .to_hex(),
                verification: retained.verification_digest().to_hex(),
            })
        } else {
            if !completed.is_empty() {
                return Err(invalid());
            }
            None
        };
        let facts = DisplayOriginalFinalRetirementFacts::new(
            scope.clone(),
            linura_observation::DisplayFinalRetirementLineage {
                record: ComponentDigest::from_bytes(sha2::Sha256::digest(&bytes).into()).to_hex(),
                preparation: record.preparation_digest().to_hex(),
                verification: record.verification_digest().to_hex(),
                current_grant: record.parent().record_digest().to_hex(),
                committed_record: record.parent().committed_record_digest().to_hex(),
            },
            u64::from(phase),
            completed,
        )
        .map_err(|_| invalid())?;
        if record.parent().frames().scope() != scope
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err(invalid());
        }
        let end_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        if began_boot == 0
            || began_wall == 0
            || end_boot
                .checked_sub(began_boot)
                .is_none_or(|age| age >= 2000)
            || now.checked_sub(began_wall).is_none_or(|age| age >= 2000)
            || started.elapsed() >= Duration::from_secs(2)
        {
            return Err(invalid());
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|_| invalid())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY,
            )
            .map_err(|_| invalid())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: began_wall,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        DisplayOriginalFinalRetirementFacts::from_envelope(&observation, scope, now)
            .map_err(|_| invalid())?;
        Ok(observation)
    }

    pub(crate) fn observe_original_display_root_retirement(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        use linura_observation::DisplayOriginalRootRetirementFacts;
        use sha2::Digest;
        self.require_role(NativeSessionRole::Control)?;
        let invalid = || "original completion lifetime unavailable; no reconstruction".to_owned();
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err(invalid());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let began_wall = crate::owner::unix_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|_| invalid())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadRootPower",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ayayayb"
            || reply.body().len()
                > crate::MAX_NATIVE_DISPLAY_ROOT_RETIREMENT
                    + crate::MAX_NATIVE_DISPLAY_CURRENT_COMMIT
                    + 384 * 1024
                    + 160
        {
            return Err(invalid());
        }
        let (bytes, preimage, current_grant, retired): (Vec<u8>, Vec<u8>, Vec<u8>, bool) =
            reply.body().deserialize().map_err(|_| invalid())?;
        if !retired {
            return Err(invalid());
        }
        let record = crate::NativeDisplayRootRetirementPreparation::decode(&bytes)?;
        let completion = record.parent().parent();
        let facts = DisplayOriginalRootRetirementFacts::new(
            linura_observation::DisplayRootRetirementLineage {
                record: ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.canonical_bytes()).into(),
                )
                .to_hex(),
                preparation: record.preparation_digest().to_hex(),
                verification: record.verification_digest().to_hex(),
                power_record: ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
                )
                .to_hex(),
            },
            crate::NativeDisplayRecoveryCheckpoint::original_protection_facts(&preimage, scope)?,
            linura_observation::DisplayOriginalCompletionFacts::new(
                linura_observation::DisplayCompletionLineage {
                    record: ComponentDigest::from_bytes(
                        sha2::Sha256::digest(completion.canonical_bytes()).into(),
                    )
                    .to_hex(),
                    preparation: completion.preparation_digest().to_hex(),
                    verification: completion.verification_digest().to_hex(),
                    material: completion.parent().terminal().material().into(),
                },
                completion.frames().clone(),
            )
            .map_err(|_| invalid())?,
            if current_grant.is_empty() {
                None
            } else {
                let grant = crate::NativeDisplayCurrentCommitPreparation::decode(&current_grant)?;
                if grant.parent().canonical_bytes() != bytes {
                    return Err(invalid());
                }
                Some(linura_observation::DisplayCurrentGrantLineage {
                    record: ComponentDigest::from_bytes(
                        sha2::Sha256::digest(&current_grant).into(),
                    )
                    .to_hex(),
                    preparation: grant.preparation_digest().to_hex(),
                    committed_record: grant.committed_record_digest().to_hex(),
                })
            },
        )
        .map_err(|_| invalid())?;
        if record.frames().scope() != scope
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err(invalid());
        }
        let end_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        if began_boot == 0
            || began_wall == 0
            || end_boot
                .checked_sub(began_boot)
                .is_none_or(|age| age >= 2000)
            || now.checked_sub(began_wall).is_none_or(|age| age >= 2000)
            || started.elapsed() >= Duration::from_secs(2)
        {
            return Err(invalid());
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|_| invalid())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY,
            )
            .map_err(|_| invalid())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: began_wall,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        DisplayOriginalRootRetirementFacts::from_envelope(&observation, scope, now)
            .map_err(|_| invalid())?;
        Ok(observation)
    }

    pub(crate) fn observe_original_display_finalization(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err("original finalization observation scope unavailable".into());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|e| e.to_string())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadFinalization",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ayuay"
        {
            return Err("original finalization observation peer or signature differs".into());
        }
        // This reply remains within the ordinary 64KiB transport limit; no
        // display-preimage size exception or another probe clock is introduced.
        let (restoration, phase, terminal): (Vec<u8>, u32, Vec<u8>) = reply
            .body()
            .deserialize()
            .map_err(|_| "original finalization observation reply is malformed")?;
        let facts = crate::original_display_observer::finalization_facts(
            scope,
            &restoration,
            phase,
            &terminal,
        )?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err(
                "original finalization service changed; no admission reconstruction".into(),
            );
        }
        let age = crate::owner::boot_ms()?
            .checked_sub(began_boot)
            .ok_or("original finalization observation clock regressed")?;
        let now = crate::owner::unix_ms()?;
        if began_boot == 0 || age >= 2000 || started.elapsed() >= Duration::from_secs(2) {
            return Err("original finalization observation exceeded its original budget".into());
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|e| e.to_string())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
            )
            .map_err(|e| e.to_string())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: now
                .checked_sub(age)
                .filter(|ms| *ms != 0)
                .ok_or("original finalization wall-clock mapping underflow")?,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        linura_observation::DisplayOriginalFinalizationFacts::from_envelope(
            &observation,
            scope,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(observation)
    }

    pub(crate) fn observe_original_display_protection(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err("original display protection observation scope unavailable".into());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|e| e.to_string())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadOriginal",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ay"
        {
            return Err("original display protection observation peer or signature differs".into());
        }
        let (payload,): (Vec<u8>,) = reply
            .body()
            .deserialize()
            .map_err(|_| "original checkpoint observation reply is malformed")?;
        let facts =
            crate::NativeDisplayRecoveryCheckpoint::original_protection_facts(&payload, scope)?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err("original protection service changed; no witness reacquisition".into());
        }
        let now_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        let age = now_boot
            .checked_sub(began_boot)
            .ok_or("original protection observation clock regressed")?;
        if began_boot == 0 || age >= 2000 || started.elapsed() >= Duration::from_secs(2) {
            return Err(
                "original display protection observation exceeded its original budget".into(),
            );
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|e| e.to_string())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
            )
            .map_err(|e| e.to_string())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: now
                .checked_sub(age)
                .filter(|ms| *ms != 0)
                .ok_or("original protection wall-clock mapping underflow")?,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        linura_observation::DisplayOriginalProtectionFacts::from_envelope(&observation, scope, now)
            .map_err(|e| e.to_string())?;
        Ok(observation)
    }
    fn display_protection_call<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        method: &str,
        body: &B,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Executor)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            method,
            body,
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "b"
        {
            return Err("display protection peer or reply is unavailable".into());
        }
        let (verified,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "display protection reply is malformed")?;
        if !verified
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
        {
            return Err("original display protection is unavailable; no retry".into());
        }
        Ok(())
    }

    pub fn begin_display_protection(&self, dispatch: &ComponentDigest) -> Result<(), String> {
        self.display_protection_call("Begin", &(dispatch.to_hex(),))
    }

    pub fn reserve_display_protection(
        &self,
        record: &crate::NativeDisplayRecoveryCheckpoint,
    ) -> Result<(), String> {
        self.display_protection_call("Reserve", &(record.canonical_bytes(),))
    }

    /// Reserve exactly once after Control's fresh prepared handoff. This
    /// private endpoint remains adapter data; the native recipient must match
    /// its kernel peer to the continuously retained original startup lease.
    /// This API never retries an ambiguous call or reconstructs a lost grant.
    pub fn reserve_display_restoration(
        &self,
        record: &crate::NativeDisplayRestorationReservation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> Result<std::os::fd::OwnedFd, String> {
        self.reserve_display_grant(
            NativeSessionRole::Executor,
            "ReserveRestoration",
            &record.canonical_bytes(),
            dispatch_deadline_unix_ms,
            sampled_boot_ms,
        )
    }

    fn reserve_display_grant(
        &self,
        role: NativeSessionRole,
        method: &'static str,
        bytes: &[u8],
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> Result<std::os::fd::OwnedFd, String> {
        self.require_role(role)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            method,
            &(bytes, dispatch_deadline_unix_ms, sampled_boot_ms),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "h"
        {
            return Err("original restoration grant peer or signature differs; no retry".into());
        }
        let (descriptor,): (zbus::zvariant::OwnedFd,) = reply
            .body()
            .deserialize()
            .map_err(|_| "original restoration grant is malformed; no retry")?;
        let descriptor: std::os::fd::OwnedFd = descriptor.into();
        let peer = rustix::net::sockopt::socket_peercred(&descriptor)
            .map_err(|_| "original restoration grant has no authenticated kernel peer")?;
        if peer.uid.as_raw() != 0
            || peer.pid.as_raw_nonzero().get() as u32 != identity.pid
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
        {
            return Err("original restoration grant service changed; no reconnection".into());
        }
        Ok(descriptor)
    }

    /// Root's exclusive durable terminal reservation and native-only channel.
    /// The channel offers no retirement, release or ordinary admission.
    /// Actual original protection remains mandatory; ambiguous calls never retry.
    pub fn reserve_display_finalization(
        &self,
        record: &crate::NativeDisplayFinalizationReservation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> Result<std::os::fd::OwnedFd, String> {
        self.reserve_display_grant(
            NativeSessionRole::Executor,
            "ReserveFinalization",
            &record.canonical_bytes(),
            dispatch_deadline_unix_ms,
            sampled_boot_ms,
        )
    }

    /// Transfer exactly one original Root native release grant only to the
    /// trusted Control adapter after a separately durable one-use decision.
    /// Root independently authenticates the actual original compositor peer
    /// and persists LNRX before acknowledging the native spend. This does not
    /// release any physical, S17, input, power or startup fence.
    pub fn reserve_control_native_release_grant(
        &self,
        record: &crate::NativeDisplayRetirementPreparation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> Result<std::os::fd::OwnedFd, String> {
        self.reserve_display_grant(
            NativeSessionRole::Control,
            "ReserveNativeReleaseGrant",
            &record.canonical_bytes(),
            dispatch_deadline_unix_ms,
            sampled_boot_ms,
        )
    }

    /// A Control-only, exact-original Root handoff. Its caller must already
    /// have durably retained its one-use terminal retirement preparation and
    /// independently revalidated terminal quiescence. This adapter derives
    /// native binding bytes from Root's OWN retained file, not reconstructed
    /// approval or client-selected execution material. Neither RPC releases
    /// native/S17/input/power fences.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_root_retired_held(
        &self,
        material: &str,
        terminal_transaction: &str,
        terminal_dispatch: &str,
        control_state_version: u64,
        control_binding: ComponentDigest,
        control_observation: ComponentDigest,
        expires_at_unix_ms: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let now = crate::owner::unix_ms()?;
        if now == 0 || now >= expires_at_unix_ms || expires_at_unix_ms - now > 2_000 {
            return Err("Root retirement Control evidence is expired or malformed".into());
        }
        let original = linura_core::DisplayFinalizationMaterial::decode(material)
            .map_err(|_| "Root retirement terminal material is invalid")?;
        let scope = original.recovery_scope().map_err(|e| e.to_string())?;
        let key = scope.resource_id().map_err(|e| e.to_string())?;
        let binding = control_binding;
        let observation = control_observation;
        if binding == ComponentDigest::from_bytes([0; 32])
            || observation == ComponentDigest::from_bytes([0; 32])
        {
            return Err("Root retirement Control anchor is not canonical".into());
        }
        let started = Instant::now();
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let read = |expected: u32| -> Result<
            (
                Vec<u8>,
                Vec<u8>,
                crate::NativeDisplayFinalizationReservation,
            ),
            String,
        > {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadFinalization",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayuay"
            {
                return Err("Root retirement readback has another peer or format".into());
            }
            let (restoration, phase, terminal): (Vec<u8>, u32, Vec<u8>) = reply
                .body()
                .deserialize()
                .map_err(|_| "Root retirement readback is malformed")?;
            let retained = crate::NativeDisplayRestorationReservation::decode(&restoration)?;
            let finalization = crate::NativeDisplayFinalizationReservation::decode(&terminal)?;
            finalization.validate_restoration(&retained)?;
            if phase != expected
                || finalization.material() != material
                || finalization.binding().transaction_id != terminal_transaction
                || finalization.binding().dispatch_digest.to_hex() != terminal_dispatch
                || retained
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|e| e.to_string())?
                    != scope
            {
                return Err("Root retirement held-native original lineage differs".into());
            }
            Ok((restoration, terminal, finalization))
        };
        let (initial_restoration, initial_terminal, terminal) = read(2)?;
        let preparation = crate::NativeDisplayRetirementPreparation::new(
            &terminal,
            control_state_version,
            binding,
            observation,
        )?;
        let bytes = preparation.canonical_bytes();
        let admit = |method: &str| -> Result<(), String> {
            if crate::owner::unix_ms()? >= expires_at_unix_ms {
                return Err("Root retirement original Control evidence expired".into());
            }
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                method,
                &(bytes.as_slice(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "b"
            {
                return Err("Root retirement writer peer or reply differs; no retry".into());
            }
            let (accepted,): (bool,) = reply
                .body()
                .deserialize()
                .map_err(|_| "Root retirement writer reply malformed; no retry")?;
            if !accepted
                || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            {
                return Err("Root retirement live original service changed; no retry".into());
            }
            Ok(())
        };
        // Neither action can be retried after a failed or lost ACK. A failed
        // second step permanently leaves a reserved, fenced preparation.
        admit("PrepareRetirement")?;
        admit("RetireHeld")?;
        let (restoration, terminal, _) = read(3)?;
        if restoration != initial_restoration
            || terminal != initial_terminal
            || crate::owner::unix_ms()? >= expires_at_unix_ms
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err("Root retirement post-publication lineage or freshness changed".into());
        }
        Ok(()) // Durable RootRetiredHeld only. No physical release.
    }

    /// An authenticated Control-only, original-Root release reservation.
    /// The caller must already own a separate durable Control release
    /// decision. This call is NOT native consumption or a physical-release
    /// credential. A lost Root acknowledgement is never retried.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_root_native_release(
        &self,
        material: &str,
        terminal_transaction: &str,
        terminal_dispatch: &str,
        control_state_version: u64,
        control_binding: ComponentDigest,
        control_observation: ComponentDigest,
        expires_at_unix_ms: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let now = crate::owner::unix_ms()?;
        if now == 0 || now >= expires_at_unix_ms || expires_at_unix_ms - now > 2_000 {
            return Err("native release reservation Control evidence expired".into());
        }
        let intended = linura_core::DisplayFinalizationMaterial::decode(material)
            .map_err(|_| "native release terminal intent malformed")?;
        let scope = intended
            .recovery_scope()
            .map_err(|error| error.to_string())?;
        let key = scope.resource_id().map_err(|error| error.to_string())?;
        let binding = control_binding;
        let observation = control_observation;
        if binding == ComponentDigest::from_bytes([0; 32])
            || observation == ComponentDigest::from_bytes([0; 32])
        {
            return Err("native release Control anchor is not canonical".into());
        }
        let started = Instant::now();
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let read = |expected_phase: u32| -> Result<
            (
                Vec<u8>,
                Vec<u8>,
                crate::NativeDisplayFinalizationReservation,
            ),
            String,
        > {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadFinalization",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayuay"
            {
                return Err("native release Root readback peer or format changed".into());
            }
            let (restoration, phase, native): (Vec<u8>, u32, Vec<u8>) = reply
                .body()
                .deserialize()
                .map_err(|_| "native release Root readback is malformed")?;
            let parent = crate::NativeDisplayRestorationReservation::decode(&restoration)?;
            let terminal = crate::NativeDisplayFinalizationReservation::decode(&native)?;
            terminal.validate_restoration(&parent)?;
            if phase != expected_phase
                || terminal.material() != material
                || terminal.binding().transaction_id != terminal_transaction
                || terminal.binding().dispatch_digest.to_hex() != terminal_dispatch
                || parent
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|error| error.to_string())?
                    != scope
            {
                return Err("native release lacks exact live RootRetiredHeld parent".into());
            }
            Ok((restoration, native, terminal))
        };
        let (before_parent, before_native, terminal) = read(3)?;
        let record = crate::NativeDisplayRetirementPreparation::new(
            &terminal,
            control_state_version,
            binding,
            observation,
        )?;
        let bytes = record.canonical_bytes();
        if crate::owner::unix_ms()? >= expires_at_unix_ms {
            return Err("native release Root reservation expired before effect".into());
        }
        // This Control-only mechanism has no physical release effect. Consume
        // exactly one Root reservation and independently re-read its new phase.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveNativeRelease",
            &(bytes.as_slice(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != root.sender)
            || reply.body().signature().to_string() != "b"
        {
            return Err("native release reservation reply peer or format differs; no retry".into());
        }
        let (accepted,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native release reservation reply is malformed; no retry")?;
        if !accepted || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
        {
            return Err("native release reservation lost its Root ownership; no retry".into());
        }
        let (after_parent, after_native, _) = read(5)?;
        if before_parent != after_parent
            || before_native != after_native
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            || crate::owner::unix_ms()? >= expires_at_unix_ms
        {
            return Err("native release reservation lost its immutable Root lineage".into());
        }
        Ok(()) // No compositor/S17/input/power release or startup admission.
    }

    /// Consume one separately durable Control native-release spend decision.
    /// A Root LNRX acknowledgement is only the irreversible before-effect
    /// boundary, NOT physical completion or Root/S17/input/power admission.
    /// Every before/after Root read uses the same original supervised peer;
    /// any missing ACK or changed source leaves the operation indeterminate.
    #[allow(clippy::too_many_arguments)]
    pub fn spend_root_native_release(
        &self,
        material: &str,
        terminal_transaction: &str,
        terminal_dispatch: &str,
        control_state_version: u64,
        control_binding: ComponentDigest,
        control_observation: ComponentDigest,
        expires_at_unix_ms: u64,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let now = crate::owner::unix_ms()?;
        if now == 0 || now >= expires_at_unix_ms || expires_at_unix_ms - now > 2_000 {
            return Err("native Root release spend Control evidence expired".into());
        }
        let intended = linura_core::DisplayFinalizationMaterial::decode(material)
            .map_err(|_| "native Root release spend terminal intent malformed")?;
        let scope = intended
            .recovery_scope()
            .map_err(|error| error.to_string())?;
        let key = scope.resource_id().map_err(|error| error.to_string())?;
        let binding = control_binding;
        let observation = control_observation;
        if control_state_version == 0
            || binding == ComponentDigest::from_bytes([0; 32])
            || observation == ComponentDigest::from_bytes([0; 32])
        {
            return Err("native Root release spend Control anchor noncanonical".into());
        }
        let started = Instant::now();
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let read = |expected_phase: u32| -> Result<
            (
                Vec<u8>,
                Vec<u8>,
                crate::NativeDisplayFinalizationReservation,
            ),
            String,
        > {
            let reply = self.call(
                &root.sender,
                "/org/linura/DisplayProtection1",
                "org.linura.DisplayProtection1",
                "ReadFinalization",
                &(key.as_str(),),
                started,
            )?;
            if reply
                .header()
                .sender()
                .is_none_or(|sender| sender.as_str() != root.sender)
                || reply.body().signature().to_string() != "ayuay"
            {
                return Err("native release spend Root owner/readback substituted".into());
            }
            let (restoration, phase, native): (Vec<u8>, u32, Vec<u8>) = reply
                .body()
                .deserialize()
                .map_err(|_| "native release spend Root response malformed")?;
            let parent = crate::NativeDisplayRestorationReservation::decode(&restoration)?;
            let terminal = crate::NativeDisplayFinalizationReservation::decode(&native)?;
            terminal.validate_restoration(&parent)?;
            if phase != expected_phase
                || terminal.material() != material
                || terminal.binding().transaction_id != terminal_transaction
                || terminal.binding().dispatch_digest.to_hex() != terminal_dispatch
                || parent
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|error| error.to_string())?
                    != scope
            {
                return Err("native Root release spend original lineage changed".into());
            }
            Ok((restoration, native, terminal))
        };
        let (before_parent, before_native, terminal) = read(5)?;
        let record = crate::NativeDisplayRetirementPreparation::new(
            &terminal,
            control_state_version,
            binding,
            observation,
        )?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            || crate::owner::unix_ms()? >= expires_at_unix_ms
        {
            return Err("native release spend Root peer or original expiry changed".into());
        }
        // From here both Control's before-effect journal and Root's one-use
        // grant are spent even if the owner reply, Root ACK or process is lost.
        if self.dispatch_original_display_native_release(&record, expires_at_unix_ms)? != 6 {
            return Err("native Root release spend outcome indeterminate; no retry".into());
        }
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err("native Root release spend lost original service".into());
        }
        let (after_parent, after_native, after_terminal) = read(6)?;
        if before_parent != after_parent
            || before_native != after_native
            || after_terminal.canonical_bytes() != terminal.canonical_bytes()
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            || crate::owner::unix_ms()? >= expires_at_unix_ms
        {
            return Err("native Root spend lacks fresh exact original ancestry".into());
        }
        Ok(()) // Attempt ACK only; physical proof and final retirement remain independent.
    }

    pub fn verify_display_protection(&self, dispatch: &ComponentDigest) -> Result<(), String> {
        self.display_protection_call("Verify", &(dispatch.to_hex(),))
    }

    /// Continue the already durably reserved operation once. The supplied
    /// digests correlate Control's retained decision; they grant no authority.
    pub fn handoff_display_continuation(
        &self,
        continuation: &crate::NativeDisplayContinuation,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Control)?;
        continuation.validate_at(crate::owner::unix_ms()?)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::Executor, started)?;
        continuation.validate_at(crate::owner::unix_ms()?)?;
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ContinueDisplayLayout",
            &continuation.wire(),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "u"
        {
            return Err("display executor decision reply identity or signature differs".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "display executor decision reply is malformed")?;
        if self.trusted_service(NativeSessionRole::Executor, Instant::now())? != identity
            || !(2..=6).contains(&phase)
        {
            return Err("display executor decision outcome is indeterminate; no retry".into());
        }
        Ok(phase)
    }

    pub(crate) fn trusted_service(
        &self,
        role: NativeSessionRole,
        started: Instant,
    ) -> Result<Identity, String> {
        let (unit, fragment, image, account) = match role {
            NativeSessionRole::Control => (
                "linura-authorityd.service",
                "/usr/lib/systemd/system/linura-authorityd.service",
                "/usr/lib/linura/linura-authorityd",
                "linura-authority",
            ),
            NativeSessionRole::Executor => (
                "linura-executor-session.service",
                "/usr/lib/systemd/system/linura-executor-session.service",
                "/usr/lib/linura/linura-executor-session",
                "root",
            ),
            NativeSessionRole::DisplayProtection => (
                "linura-display-protection.service",
                "/usr/lib/systemd/system/linura-display-protection.service",
                "/usr/lib/linura/linura-executor-session",
                "root",
            ),
        };
        let sender: String = self
            .bus_call("GetNameOwner", &(role.service(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native named service has no unique owner".to_owned())?;
        let credentials: HashMap<String, OwnedValue> = self
            .bus_call("GetConnectionCredentials", &(sender.as_str(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native named service credentials are malformed".to_owned())?;
        let uid: u32 = field(&credentials, "UnixUserID")?;
        let pid: u32 = field(&credentials, "ProcessID")?;
        let expected_uid = match role {
            NativeSessionRole::Executor | NativeSessionRole::DisplayProtection => 0,
            NativeSessionRole::Control => {
                crate::account::local_service_uid(crate::account::LocalServiceAccount::Authority)?
            }
        };
        if uid != expected_uid || pid == 0 {
            return Err("native named service has the wrong kernel identity".into());
        }
        let supervisor: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.systemd1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native supervisor has no unique owner".to_owned())?;
        let supervisor_uid: u32 = self
            .bus_call("GetConnectionUnixUser", &(supervisor.as_str(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native supervisor credentials are malformed".to_owned())?;
        if supervisor_uid != 0 {
            return Err("native supervisor is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &supervisor,
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(unit,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native service unit is unavailable".to_owned())?;
        if path.as_str().len() > 256
            || !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
        {
            return Err("native service unit handle is unsupported".into());
        }
        let get = |interface| -> Result<HashMap<String, OwnedValue>, String> {
            self.call(
                &supervisor,
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &(interface,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native named service properties are malformed".into())
        };
        let facts = get("org.freedesktop.systemd1.Unit")?;
        let service = get("org.freedesktop.systemd1.Service")?;
        let invocation: Vec<u8> = array(&facts, "InvocationID")?;
        let drop_ins: Vec<String> = array(&facts, "DropInPaths")?;
        let launches: Vec<ExecStart> = array(&service, "ExecStart")?;
        if field::<u32>(&service, "MainPID")? != pid
            || field::<&str>(&service, "User")? != account
            || field::<&str>(&facts, "FragmentPath")? != fragment
            || !drop_ins.is_empty()
            || field::<&str>(&facts, "ActiveState")? != "active"
            || field::<&str>(&facts, "SubState")? != "running"
            || invocation.len() != 16
            || invocation.iter().all(|b| *b == 0)
            || !live_launch(role, image, pid, &launches)
            || !crate::owner::immutable_file(std::path::Path::new(fragment), false)
            || !crate::owner::immutable_file(std::path::Path::new(image), true)
        {
            return Err("native service is not the exact immutable supervised invocation".into());
        }
        for (name, expected) in [
            (role.service(), sender.as_str()),
            ("org.freedesktop.systemd1", supervisor.as_str()),
        ] {
            let fresh: String = self
                .bus_call("GetNameOwner", &(name,), started)?
                .body()
                .deserialize()
                .map_err(|_| "native named service recheck failed".to_owned())?;
            if fresh != expected {
                return Err("native service owner changed during attestation".into());
            }
        }
        Ok(Identity {
            sender,
            uid,
            pid,
            invocation,
        })
    }

    /// Executor-only caller authentication. This is not policy approval; the
    /// service must separately authorize the fixed native executor action and
    /// validate the exact prepared binding before dispatch.
    pub fn require_trusted_control_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::Executor)?;
        if sender.len() > 128
            || self
                .trusted_service(NativeSessionRole::Control, Instant::now())?
                .sender
                != sender
        {
            return Err("session executor caller is not the supervised Control owner".into());
        }
        Ok(())
    }

    /// The protection process accepts only the current independently supervised
    /// session executor. Root UID or possession of a dispatch digest is not
    /// sufficient. This admits a bounded mechanism, not a new effect path.
    pub fn require_trusted_display_executor_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        if !crate::owner::unique_name(sender)
            || self
                .trusted_service(NativeSessionRole::Executor, Instant::now())?
                .sender
                != sender
        {
            return Err("display protection caller is not the supervised executor".into());
        }
        Ok(())
    }

    /// Private original-protection queries and prepared continuations admit
    /// the exact supervised Control invocation, never account identity alone.
    pub fn require_trusted_display_control_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        if !crate::owner::unique_name(sender)
            || self
                .trusted_service(NativeSessionRole::Control, Instant::now())?
                .sender
                != sender
        {
            return Err(
                "original display observation requires the supervised Control owner".into(),
            );
        }
        Ok(())
    }

    /// Control-only, single-attempt handoff. A failed/uncertain reply is never
    /// retried here. The managed lifecycle already persisted ambiguity before
    /// consuming its process-local permit and calling this adapter.
    pub fn handoff_prepared_lock(
        &self,
        lock: &SessionLockId,
        secure: bool,
        binding: &ExecutionBinding,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::Executor, started)?;
        let resource = lock.resource_id().map_err(|e| e.to_string())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "SetSecure",
            &(
                resource.as_str(),
                secure,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            started,
        )?;
        self.decode_executor_outcome(&identity, reply, binding, started)
    }

    pub fn handoff_prepared_transition(
        &self,
        target: &SessionTransitionId,
        binding: &ExecutionBinding,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        let resource = target.resource_id().map_err(|e| e.to_string())?;
        // Fixed aggregate mechanism budget, not a human interaction deadline.
        // The root service rechecks native preconditions and arms coverage;
        // any late/lost response remains durable ambiguity, never an OS retry.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ExecuteTransition",
            &(
                resource.as_str(),
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    /// Single prepared full-layout handoff. Neither this adapter nor the root
    /// executor can manufacture a Control permit from the correlation binding.
    /// Native strict validation preserves its own original two-second sample.
    pub fn handoff_prepared_display(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let effect = linura_provider_sdk::display_layout_effect(material)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        // Separate fixed mechanism budget, including root's service policy and
        // one native probe/dispatch. It cannot extend the human deadline or the
        // native sample's freshness. Fault/timeout never requests redelivery.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ApplyDisplayLayout",
            &(
                material,
                deadline_unix_ms,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
                native_baseline_guard.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
        {
            return Err(
                "prepared display executor result has a different authenticated sender".into(),
            );
        }
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    /// Fresh sealed Control handoff; historical Apply approvals cannot reach it.
    pub fn handoff_original_display_restoration(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let effect = linura_provider_sdk::display_restoration_effect(material)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        // Separate fixed mechanism budget, including root's service policy and
        // one native probe/dispatch. It cannot extend the human deadline or the
        // native sample's freshness. Fault/timeout never requests redelivery.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "RestoreOriginalDisplayLayout",
            &(
                material,
                deadline_unix_ms,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
        {
            return Err(
                "original restoration executor result has a different authenticated sender".into(),
            );
        }
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    /// Separately prepared terminal-purpose handoff; acknowledgement is not completion.
    pub fn handoff_original_display_finalization(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let effect = linura_provider_sdk::display_finalization_effect(material)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        // Separate fixed mechanism budget, including root's service policy and
        // one native probe/dispatch. It cannot extend the human deadline or the
        // native sample's freshness. Fault/timeout never requests redelivery.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "QuiesceOriginalDisplayFinalization",
            &(
                material,
                deadline_unix_ms,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
        {
            return Err(
                "original restoration executor result has a different authenticated sender".into(),
            );
        }
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    fn decode_executor_outcome(
        &self,
        identity: &Identity,
        reply: zbus::Message,
        binding: &ExecutionBinding,
        started: Instant,
    ) -> Result<ExecutionOutcome, String> {
        let ((disposition, digest, detail),): ((String, String, String),) = reply
            .body()
            .deserialize()
            .map_err(|_| "native executor outcome is malformed".to_owned())?;
        if &self.trusted_service(NativeSessionRole::Executor, started)? != identity {
            return Err("native executor changed across dispatch; outcome is indeterminate".into());
        }
        let disposition = match disposition.as_str() {
            "dispatched" => ExecutionDisposition::Dispatched,
            "rejected-before-dispatch" => ExecutionDisposition::RejectedBeforeDispatch,
            "indeterminate" => ExecutionDisposition::Indeterminate,
            _ => return Err("native executor disposition is unknown".into()),
        };
        if detail.len() > 192
            || ComponentDigest::parse_hex(&digest).map_err(|e| e.to_string())?
                != binding.dispatch_digest
        {
            return Err("native executor substituted its exact handoff binding".into());
        }
        ExecutionOutcome::new(disposition, binding.dispatch_digest, detail)
            .map_err(|e| e.to_string())
    }
}

pub(crate) fn field<'a, T: TryFrom<&'a OwnedValue>>(
    properties: &'a HashMap<String, OwnedValue>,
    name: &str,
) -> Result<T, String> {
    properties
        .get(name)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| format!("native named service field {name} is absent or malformed"))
}
pub(crate) fn array<T>(
    properties: &HashMap<String, OwnedValue>,
    name: &str,
) -> Result<Vec<T>, String>
where
    for<'a> T: TryFrom<zbus::zvariant::Value<'a>>,
    for<'a> <T as TryFrom<zbus::zvariant::Value<'a>>>::Error: Into<zbus::zvariant::Error>,
{
    let value = properties
        .get(name)
        .ok_or("native service array field is absent")?
        .try_clone()
        .map_err(|_| "native service array field is unavailable".to_owned())?;
    Vec::<T>::try_from(value).map_err(|_| "native service array field has the wrong type".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_mode_is_not_an_executor_or_control_launch() {
        let image = "/usr/lib/linura/linura-executor-session";
        let original: ExecStart = (
            image.into(),
            vec![image.into(), "--display-protection".into()],
            false,
            1,
            2,
            0,
            0,
            42,
            0,
            0,
        );
        assert!(live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            std::slice::from_ref(&original)
        ));
        for role in [NativeSessionRole::Control, NativeSessionRole::Executor] {
            assert!(!live_launch(
                role,
                image,
                42,
                std::slice::from_ref(&original)
            ));
            let mut regular = original.clone();
            regular.1.pop();
            assert!(live_launch(role, image, 42, std::slice::from_ref(&regular)));
            assert!(!live_launch(
                NativeSessionRole::DisplayProtection,
                image,
                42,
                &[regular]
            ));
        }
        for change in 0..12 {
            let mut bad = original.clone();
            match change {
                0 => bad.0 = "/tmp/executor".into(),
                1 => bad.1[0] = "/tmp/executor".into(),
                2 => bad.1[1] = "--protect-before-sleep".into(),
                3 => bad.1.push("unexpected".into()),
                4 => bad.2 = true,
                5 => bad.3 = 0,
                6 => bad.4 = 0,
                7 => bad.5 = 3,
                8 => bad.6 = 4,
                9 => bad.7 = 43,
                10 => bad.8 = 1,
                11 => bad.9 = 1,
                _ => unreachable!(),
            }
            assert!(
                !live_launch(NativeSessionRole::DisplayProtection, image, 42, &[bad]),
                "field {change}"
            );
        }
        assert!(!live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            &[]
        ));
        assert!(!live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            &[original.clone(), original]
        ));
    }
}
