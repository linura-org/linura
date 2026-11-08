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
