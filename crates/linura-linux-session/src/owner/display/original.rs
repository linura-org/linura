//! One fresh original-restoration handoff. Root reserves the immutable source
//! once; this adapter never retries, reconstructs a grant or retires a fence.
use super::*;
use linura_provider_sdk::ExecutionBinding;

fn validate_deadline(deadline: u64, now: u64) -> Result<(), String> {
    if now == 0 || deadline <= now || deadline - now > 15_000 {
        return Err("original restoration dispatch deadline is expired or unsupported".into());
    }
    Ok(())
}
fn validate_handoff(
    material: &str,
    binding: &ExecutionBinding,
    deadline: u64,
    now: u64,
) -> Result<crate::NativeDisplayRestorationReservation, String> {
    validate_deadline(deadline, now)?;
    let transaction = &binding.transaction_id;
    if transaction.len() <= "transaction:".len()
        || transaction.len() > 256
        || !transaction.starts_with("transaction:")
        || !transaction
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'-'))
    {
        return Err("original restoration correlation is malformed".into());
    }
    crate::NativeDisplayRestorationReservation::new(material, binding)
}
impl NativeSessionChannel {
    pub fn dispatch_original_display_restoration(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Executor)?;
        let reservation = validate_handoff(material, binding, deadline_unix_ms, unix_ms()?)?;
        let decoded = reservation.decoded_material()?;
        let sample = self.prepared_display_material(decoded.replacement(), 1)?;
        let guard =
            linura_provider_sdk::ComponentDigest::parse_hex(decoded.replacement_baseline_guard())
                .map_err(|e| e.to_string())?;
        if sample.native_baseline_guard.as_ref() != Some(&guard) {
            return Err("replacement canonical native baseline changed before restoration".into());
        }
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_deadline(deadline_unix_ms, unix_ms()?)?;
        let before = boot_ms()?;
        if before < sample.sampled_boot_ms || before - sample.sampled_boot_ms >= 2000 {
            return Err("original restoration sample expired before reservation".into());
        }
        // Exclusive durable reservation precedes disclosure. Any later fault,
        // owner drift or timeout leaves it spent; do not request another FD.
        let grant = self.reserve_display_restoration(
            &reservation,
            deadline_unix_ms,
            sample.sampled_boot_ms,
        )?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        validate_deadline(deadline_unix_ms, unix_ms()?)?;
        let after = boot_ms()?;
        if after < sample.sampled_boot_ms || after - sample.sampled_boot_ms >= 2000 {
            return Err("original restoration sample expired during reservation".into());
        }
        let grant = zbus::zvariant::OwnedFd::from(grant);
        let reply = self.call_with_budget(
            &sample.owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "RestoreOriginalDisplay",
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
            return Err("original restoration reply peer or signature differs; no retry".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "original restoration reply is malformed; no retry")?;
        self.revalidate_observation(&sample.owner, &sample.boot, sample.started)?;
        // Acknowledgement only. No phase is terminal verification or release.
        match phase {
            1 | 3 | 6..=8 => Ok(phase),
            _ => Err("original restoration reply has an unsupported phase".into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use linura_provider_sdk::{ComponentDigest, display_restoration_effect};
    #[test]
    fn original_handoff_keeps_distinct_effect_scope_and_original_deadline() {
        let material = include_str!(
            "../../../../linura-core/src/display_recovery/fixtures/original-baseline.txt"
        )
        .trim_end();
        let effect = display_restoration_effect(material).unwrap_or_else(|_| unreachable!());
        let binding = ExecutionBinding::new(
            "transaction:original-handoff",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(validate_handoff(material, &binding, 25_000, 10_000).is_ok());
        for (deadline, now) in [(0, 10_000), (10_000, 10_000), (25_001, 10_000), (25_000, 0)] {
            assert!(validate_handoff(material, &binding, deadline, now).is_err());
        }
        assert!(validate_handoff("LNDI:1;", &binding, 25_000, 10_000).is_err());
        let mut changed = binding.clone();
        changed.effect_digest = ComponentDigest::from_bytes([3; 32]);
        assert!(validate_handoff(material, &changed, 25_000, 10_000).is_err());
        changed = binding.clone();
        changed.transaction_id = "transaction:UPPER".into();
        assert!(validate_handoff(material, &changed, 25_000, 10_000).is_err());
    }
}
