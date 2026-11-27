//! One fresh purpose-13 managed handoff. Root/native ACK is not post-effect
//! verification, terminal completion, power/input retirement or cleanup authority.
use super::*;
use linura_provider_sdk::{ExecutionBinding, ExecutionDisposition, ExecutionOutcome};

impl NativeSessionChannel {
    pub(crate) fn observe_ordinary_display_release(
        &self,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        use linura_observation::{
            DISPLAY_ORDINARY_RELEASE_CAPABILITY, DISPLAY_RECOVERY_PROVIDER,
            DisplayNativeHandoffWindow, DisplayOrdinaryReleaseComparison,
            DisplayOrdinaryReleaseFacts,
        };
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let boot = current_boot()?;
        if sequence == 0 || boot != *scope.topology().session().boot() {
            return Err(unavailable());
        }
        let began_wall = unix_ms()?;
        let began_boot = boot_ms()?;
        let root = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|_| unavailable())?;
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadOrdinaryRelease",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|s| s.as_str() != root.sender)
            || reply.body().signature().to_string() != "ayb"
            || reply.body().len() > crate::MAX_NATIVE_DISPLAY_ORDINARY_RELEASE + 32
        {
            return Err(unavailable());
        }
        let (bytes, spent): (Vec<u8>, bool) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        let record = crate::NativeDisplayOrdinaryReleasePreparation::decode(&bytes)?;
        if record
            .decoded_material()?
            .release_scope()
            .map_err(|_| unavailable())?
            != *scope
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            || current_boot()? != boot
        {
            return Err(unavailable());
        }
        let wall = unix_ms()?;
        let sampled_boot_ms = boot_ms()?;
        require_window(&record, wall, sampled_boot_ms)?;
        if wall.checked_sub(began_wall).is_none_or(|age| age >= 2000)
            || sampled_boot_ms
                .checked_sub(began_boot)
                .is_none_or(|age| age >= 2000)
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err(unavailable());
        }
        let facts = DisplayOrdinaryReleaseFacts::new(
            scope.clone(),
            DisplayOrdinaryReleaseComparison {
                material: record.material().into(),
                transaction: record.binding().transaction_id.clone(),
                effect: record.binding().effect_digest.to_hex(),
                dispatch: record.binding().dispatch_digest.to_hex(),
                preparation_digest: record.record_digest().to_hex(),
                spent,
                producer: record.window(),
                sampled_boot_ms,
            },
        )
        .map_err(|_| unavailable())?;
        let observation = ObservationEnvelope {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| unavailable())?,
            capability: CapabilityId::new(DISPLAY_ORDINARY_RELEASE_CAPABILITY)
                .map_err(|_| unavailable())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: wall,
            valid_for_ms: DisplayNativeHandoffWindow {
                observed_unix_ms: wall,
                observed_boot_ms: sampled_boot_ms,
                ..record.window()
            }
            .valid_for_ms()
            .map_err(|_| unavailable())?,
            sequence,
            attributes: facts.attributes(),
        };
        DisplayOrdinaryReleaseFacts::from_envelope(&observation, scope, unix_ms()?)
            .map_err(|_| unavailable())?;
        require_window(&record, unix_ms()?, boot_ms()?)?;
        Ok(observation)
    }

    pub fn dispatch_ordinary_display_release(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let effect = linura_provider_sdk::display_ordinary_release_effect(material)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let intent = linura_core::DisplayOrdinaryReleaseMaterial::decode(material)
            .map_err(|e| e.to_string())?;
        let started = Instant::now();
        let boot = current_boot()?;
        if boot != *intent.original().topology().session().boot() {
            return Err(unavailable());
        }
        let owner = self.discover(intent.current_lock().epoch().uid(), started)?;
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveDisplay",
            &(),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "(ssstssb)"
        {
            return Err(unavailable());
        }
        let (sample,): (Wire,) = reply.body().deserialize().map_err(|_| unavailable())?;
        if sample.0.len() > 256
            || sample.1.len() > 36
            || sample.2.len() > 32
            || sample.4.len() > 64 * 1024
            || sample.5.len() > 256 * 1024
        {
            return Err(unavailable());
        }
        let digest = sample_digest(&sample);
        self.revalidate_observation(&owner, &boot, started)?;
        let wall = unix_ms()?;
        let coverage = observation(
            &owner,
            &boot,
            &sample.0,
            sample.6,
            sample.3,
            boot_ms()?,
            wall,
            1,
        )?;
        if coverage.resource
            != intent
                .current_lock()
                .resource_id()
                .map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        let (display, covered) = project(coverage, &sample.1, &sample.2, &sample.4, &sample.5)?;
        let outputs = covered.attributes.get("observed_outputs");
        let locked = covered.attributes.get("covered_outputs");
        if (sample.6 && outputs != locked)
            || (!sample.6 && locked != Some(&ObservedValue::Text(String::new())))
        {
            return Err(unavailable());
        }
        let facts = linura_observation::DisplayObservationFacts::from_envelope(
            &display,
            intent.original().topology(),
            unix_ms()?,
        )
        .map_err(|_| unavailable())?;
        let target = intent
            .validate_native(facts.inventory(), facts.capabilities())
            .map_err(|_| unavailable())?;
        if facts.layout() != &target
            || !facts.has_powered_independent_output()
            || linura_provider_sdk::display_baseline_guard(&facts)?.to_hex()
                != intent.lineage().current_source_guard
        {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        let (record, root) =
            self.reserve_ordinary_release_record(material, binding, deadline_unix_ms, started)?;
        // This exact Root invocation and complete original producer window are
        // retained; the read-only phase query cannot recreate the descriptor.
        let reply = self.call(
            &root.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveOrdinaryReleaseGrant",
            &(record.canonical_bytes(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|s| s.as_str() != root.sender)
            || reply.body().signature().to_string() != "h"
            || reply.body().len() > 8
        {
            return Err(unavailable());
        }
        let (grant,): (zbus::zvariant::OwnedFd,) =
            reply.body().deserialize().map_err(|_| unavailable())?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root {
            return Err(unavailable());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        require_window(&record, unix_ms()?, boot_ms()?)?;
        let before = boot_ms()?;
        if before < sample.3 || before - sample.3 >= 2000 {
            return Err(unavailable());
        }
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "SpendOrdinaryDisplayRelease",
            &(
                (
                    material,
                    binding.transaction_id.as_str(),
                    binding.effect_digest.to_hex(),
                    binding.dispatch_digest.to_hex(),
                    deadline_unix_ms,
                ),
                digest.to_hex(),
                sample.3,
                grant,
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|s| s.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "b"
            || reply.body().len() > 8
        {
            return Err(unavailable());
        }
        let (accepted,): (bool,) = reply.body().deserialize().map_err(|_| unavailable())?;
        self.revalidate_observation(&owner, &boot, started)?;
        require_window(&record, unix_ms()?, boot_ms()?)?;
        if !accepted
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != root
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err(unavailable());
        }
        ExecutionOutcome::new(ExecutionDisposition::Dispatched,binding.dispatch_digest,
            "ordinary native handoff attempted; independent first-frame and completion verification required")
            .map_err(|e| e.to_string())
    }
}

fn require_window(
    record: &crate::NativeDisplayOrdinaryReleasePreparation,
    wall: u64,
    boot: u64,
) -> Result<(), String> {
    let window = record.window();
    if wall < window.observed_unix_ms
        || boot < window.observed_boot_ms
        || wall >= window.deadline_unix_ms
        || boot >= window.deadline_boot_ms
    {
        Err(unavailable())
    } else {
        Ok(())
    }
}
fn unavailable() -> String {
    "ordinary native release unavailable or ambiguous; no replay".into()
}
