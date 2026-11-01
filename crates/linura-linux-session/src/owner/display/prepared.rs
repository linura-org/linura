//! Single-attempt prepared display handoff on the SAME independently attested
//! native owner. No caller-selected sender, retry, reconnection or approval.
use super::*;
use linura_provider_sdk::{ExecutionBinding, display_layout_effect};

fn validate_handoff(
    material: &str,
    binding: &ExecutionBinding,
    deadline_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), String> {
    let effect = display_layout_effect(material)?;
    binding.validate_for(&effect).map_err(|e| e.to_string())?;
    // Reuse exactly the compositor attempt's closed correlation grammar.
    attempt::Query::new(
        material,
        &binding.transaction_id,
        &binding.dispatch_digest,
        deadline_unix_ms,
    )?;
    if now_unix_ms == 0
        || deadline_unix_ms <= now_unix_ms
        || deadline_unix_ms - now_unix_ms > 15_000
    {
        return Err("prepared display confirmation deadline is expired or unsupported".into());
    }
    Ok(())
}

impl NativeSessionChannel {
    /// Narrow root executor mechanism after separate Control/service admission.
    /// Binding hashes correlate the prepared effect; they are not credentials.
    /// All metadata validation, dispatch and post-reply revalidation consume the
    /// original probe clock. A late/lost reply is never retried or re-discovered.
    pub fn dispatch_prepared_display(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &linura_provider_sdk::ComponentDigest,
        checkpoint: impl FnOnce(&NativeDisplayRecoveryCheckpoint) -> Result<(), String>,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Executor)?;
        validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let sample = self.prepared_display_sample(material, 1)?;
        if sample.native_baseline_guard.as_ref() != Some(native_baseline_guard) {
            return Err(
                "original canonical native baseline changed before executor dispatch".into(),
            );
        }
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let now_boot_ms = boot_ms()?;
        if now_boot_ms < sample.sampled_boot_ms || now_boot_ms - sample.sampled_boot_ms >= 2000 {
            return Err("prepared display sample expired before dispatch".into());
        }
        // Native preimages must survive independently BEFORE the first write.
        // The fixed executor callback persists this validated opaque record and
        // retains the operation's narrow recovery protections. It is not policy,
        // an effect dispatcher or client-supplied orchestration. Failure never
        // reaches native apply.
        let record =
            NativeDisplayRecoveryCheckpoint::capture(material, binding, deadline_unix_ms, &sample)?;
        checkpoint(&record)?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let after_checkpoint_boot_ms = boot_ms()?;
        if after_checkpoint_boot_ms < sample.sampled_boot_ms
            || after_checkpoint_boot_ms - sample.sampled_boot_ms >= 2000
        {
            return Err("prepared display sample expired during durable checkpoint".into());
        }
        let query = (
            material,
            binding.transaction_id.as_str(),
            binding.effect_digest.to_hex(),
            binding.dispatch_digest.to_hex(),
            deadline_unix_ms,
        );
        let reply = self.call_with_budget(
            &sample.owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "DispatchPreparedDisplay",
            &(
                query,
                sample.digest.to_hex(),
                sample.sampled_boot_ms,
                native_baseline_guard.to_hex(),
            ),
            owner_reply_budget(sample.started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != sample.owner.unique_name)
        {
            return Err(
                "prepared native display result has a different authenticated sender".into(),
            );
        }
        if reply.body().signature().to_string() != "u" {
            return Err("prepared native display result signature mismatch".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "prepared native display result codec mismatch")?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        if !(1..=8).contains(&phase) {
            return Err("prepared native display result is unsupported".into());
        }
        Ok(phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_provider_sdk::ComponentDigest;

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (String, ExecutionBinding) {
        let lock = super::super::tests::coverage(true).resource;
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = |x| format!("LNDL:1;{topology};1:2:enabled:1920:1080:59940:1250:0:{x}:0:-;");
        let material = format!("LNDI:1;{};{}{}", lock.as_str(), layout(0), layout(100));
        let effect = value(display_layout_effect(&material));
        let binding = value(ExecutionBinding::new(
            "transaction:display-test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        (material, binding)
    }

    #[test]
    fn prepared_handoff_rejects_substituted_effect_correlation_and_original_deadline() {
        let (material, binding) = fixture();
        assert!(validate_handoff(&material, &binding, 25_000, 10_000).is_ok());
        for (deadline, now) in [(0, 10_000), (10_000, 10_000), (25_001, 10_000), (25_000, 0)] {
            assert!(validate_handoff(&material, &binding, deadline, now).is_err());
        }
        assert!(
            validate_handoff(
                &material.replace(":100:0:-;", ":101:0:-;"),
                &binding,
                25_000,
                10_000
            )
            .is_err()
        );
        let mut substituted = binding.clone();
        substituted.dispatch_digest = ComponentDigest::from_bytes([0; 32]);
        assert!(validate_handoff(&material, &substituted, 25_000, 10_000).is_err());
        substituted = binding.clone();
        substituted.transaction_id = "transaction:UPPER".into();
        assert!(validate_handoff(&material, &substituted, 25_000, 10_000).is_err());
        assert!(validate_handoff("not a display intent", &binding, 25_000, 10_000).is_err());
    }
}
