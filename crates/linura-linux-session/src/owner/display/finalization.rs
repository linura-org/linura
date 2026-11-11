//! One separately prepared terminal handoff. No old approval, reconnect,
//! retry or acknowledgement may release protection or commit completion.
use super::*;
use linura_provider_sdk::ExecutionBinding;

fn validate_handoff(
    material: &str,
    binding: &ExecutionBinding,
    deadline: u64,
    now: u64,
) -> Result<crate::NativeDisplayFinalizationReservation, String> {
    if now == 0 || deadline <= now || deadline - now > 15_000 {
        return Err("terminal dispatch deadline is expired or unsupported".into());
    }
    let transaction = &binding.transaction_id;
    if transaction.len() <= "transaction:".len()
        || transaction.len() > 256
        || !transaction.starts_with("transaction:")
        || !transaction
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'-'))
    {
        return Err("terminal dispatch correlation is malformed".into());
    }
    crate::NativeDisplayFinalizationReservation::new(material, binding)
}

impl NativeSessionChannel {
    /// Control-only original terminal release SPEND. Not a finalization
    /// commit, ordinary startup admission or physical first-frame receipt.
    /// Unlike Executor-only prepared dispatch this independently samples the
    /// Control-authorized owner through ObserveDisplay and never inherits an
    /// executor handle or a reusable Root credential.
    pub fn dispatch_original_display_native_release(
        &self,
        record: &crate::NativeDisplayRetirementPreparation,
        deadline_unix_ms: u64,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Control)?;
        let now = unix_ms()?;
        if deadline_unix_ms <= now || deadline_unix_ms - now > 15_000 {
            return Err("original native release has expired original deadline".into());
        }
        let terminal_record = record.terminal();
        let terminal = terminal_record.decoded_material()?;
        let restored = terminal.restoration().replacement();
        if terminal.current_lock() != restored.lock() {
            return Err("original native release lock differs from restoration".into());
        }
        let started = Instant::now();
        let boot = current_boot()?;
        let owner = self.discover(terminal.current_lock().epoch().uid(), started)?;
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
            return Err("native release Control owner observation is substituted".into());
        }
        let (sample,): (Wire,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native release Control owner observation is malformed")?;
        if sample.0.len() > 256
            || sample.1.len() > 36
            || sample.2.len() > 32
            || sample.4.len() > 64 * 1024
            || sample.5.len() > 256 * 1024
        {
            return Err("native release owner sample exceeds its bound".into());
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
            != terminal
                .current_lock()
                .resource_id()
                .map_err(|e| e.to_string())?
        {
            return Err("native release lock incarnation changed".into());
        }
        let (display, covered) = project(coverage, &sample.1, &sample.2, &sample.4, &sample.5)?;
        let active = covered.attributes.get("observed_outputs");
        let locked = covered.attributes.get("covered_outputs");
        if sample.6 && active != locked
            || !sample.6 && locked != Some(&ObservedValue::Text(String::new()))
        {
            return Err("native release independent output coverage is incomplete".into());
        }
        let facts = linura_observation::DisplayObservationFacts::from_envelope(
            &display,
            restored.topology(),
            unix_ms()?,
        )
        .map_err(|e| e.to_string())?;
        validate_prepared_layout(restored, &facts, SampleLayout::Restored)?;
        let source = facts
            .recovery_metadata()
            .ok_or("native release has no original recovered source")?;
        let _ = source;
        if linura_provider_sdk::display_baseline_guard(&facts)?.to_hex()
            != terminal.restored_source_guard()
        {
            return Err("native release current source differs from original restoration".into());
        }
        if started.elapsed() >= crate::bus::PROBE_BUDGET {
            return Err("native release original Control sample expired".into());
        }
        display
            .require_current(unix_ms()?)
            .map_err(|e| e.to_string())?;
        let before = boot_ms()?;
        if before < sample.3 || before - sample.3 >= 2_000 {
            return Err("native release original BOOTTIME sample expired".into());
        }
        // The Root grant is consumed at most once. An owner, bus or kernel
        // failure from here never rebuilds this descriptor or replays LNRX.
        let grant =
            self.reserve_control_native_release_grant(record, deadline_unix_ms, sample.3)?;
        self.revalidate_observation(&owner, &boot, started)?;
        let after = boot_ms()?;
        if after < sample.3 || after - sample.3 >= 2_000 {
            return Err("native release Root transfer exceeded original clock".into());
        }
        let binding = terminal_record.binding();
        let grant = zbus::zvariant::OwnedFd::from(grant);
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "SpendOriginalDisplayNativeRelease",
            &(
                (
                    terminal_record.material(),
                    binding.transaction_id.as_str(),
                    binding.effect_digest.to_hex(),
                    binding.dispatch_digest.to_hex(),
                    deadline_unix_ms,
                ),
                digest.to_hex(),
                sample.3,
                record.control_state_version(),
                record.control_binding().to_hex(),
                record.control_observation().to_hex(),
                grant,
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "u"
        {
            return Err("native release owner ACK is substituted; no replay".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native release ACK is malformed; no replay")?;
        self.revalidate_observation(&owner, &boot, started)?;
        if phase != 6 {
            return Err("native Root grant spend not confirmed; no replay".into());
        }
        Ok(phase) // Attempt ACK only, never independent physical or terminal completion.
    }

    pub fn dispatch_original_display_finalization(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Executor)?;
        let record = validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let terminal = record.decoded_material()?;
        let sample = self.prepared_restored_display_material(&terminal, 1)?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let before = boot_ms()?;
        if before < sample.sampled_boot_ms || before - sample.sampled_boot_ms >= 2000 {
            return Err("terminal native sample expired before reservation".into());
        }
        // Exactly one Root reservation, never a reconstructed endpoint. Any
        // failure after this point leaves memory/history ownership spent.
        let grant =
            self.reserve_display_finalization(&record, deadline_unix_ms, sample.sampled_boot_ms)?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let after = boot_ms()?;
        if after < sample.sampled_boot_ms || after - sample.sampled_boot_ms >= 2000 {
            return Err("terminal native sample expired during reservation".into());
        }
        let grant = zbus::zvariant::OwnedFd::from(grant);
        let reply = self.call_with_budget(
            &sample.owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "QuiesceOriginalDisplayFinalization",
            &(
                (
                    material,
                    binding.transaction_id.as_str(),
                    binding.effect_digest.to_hex(),
                    binding.dispatch_digest.to_hex(),
                    deadline_unix_ms,
                ),
                sample.digest.to_hex(),
                sample.sampled_boot_ms,
                grant,
            ),
            owner_reply_budget(sample.started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != sample.owner.unique_name)
            || reply.body().signature().to_string() != "u"
        {
            return Err("terminal native reply peer or signature differs; no retry".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "terminal native reply is malformed; no retry")?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        match phase {
            2 => Ok(phase), // Quiescence acknowledgement only; never release or verification.
            _ => Err("terminal native reply is unavailable or unsupported; no retry".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_provider_sdk::{ComponentDigest, display_finalization_effect};
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn terminal_handoff_requires_separate_effect_correlation_and_original_deadline() {
        let material = include_str!(
            "../../../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
        )
        .trim_end();
        let effect = value(display_finalization_effect(material));
        let binding = value(ExecutionBinding::new(
            "transaction:terminal-handoff",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        assert!(validate_handoff(material, &binding, 25_000, 10_000).is_ok());
        for (deadline, now) in [(0, 10_000), (10_000, 10_000), (25_001, 10_000), (25_000, 0)] {
            assert!(validate_handoff(material, &binding, deadline, now).is_err());
        }
        for transaction in ["transaction:", "transaction:UPPER", "foreign", ""] {
            let mut changed = binding.clone();
            changed.transaction_id = transaction.into();
            assert!(validate_handoff(material, &changed, 25_000, 10_000).is_err());
        }
        let mut changed = binding.clone();
        changed.effect_digest = ComponentDigest::from_bytes([3; 32]);
        assert!(validate_handoff(material, &changed, 25_000, 10_000).is_err());
        let old = value(linura_core::DisplayFinalizationMaterial::decode(material))
            .restoration_text()
            .to_owned();
        assert!(validate_handoff(&old, &binding, 25_000, 10_000).is_err());
    }
}
