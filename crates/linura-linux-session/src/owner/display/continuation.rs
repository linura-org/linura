//! Bounded comparison data for one already prepared display decision. This
//! adapter value is neither a permit nor proof of human interaction. Only the
//! independently attested Control service may reach the executor, and only that
//! executor may reach the original protected native owner/connection.
use super::*;
use linura_provider_sdk::ComponentDigest;

#[derive(Debug)]
pub struct NativeDisplayContinuation {
    material: String,
    transaction: String,
    dispatch: ComponentDigest,
    deadline: u64,
    decision: ComponentDigest,
    protected_decision: ComponentDigest,
    confirm: bool,
}
impl NativeDisplayContinuation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        material: &str,
        transaction: &str,
        dispatch: ComponentDigest,
        deadline: u64,
        decision: ComponentDigest,
        protected_decision: ComponentDigest,
        confirm: bool,
    ) -> Result<Self, String> {
        if material.len() > linura_core::MAX_DISPLAY_INTENT_BYTES
            || [decision, protected_decision].contains(&ComponentDigest::from_bytes([0; 32]))
        {
            return Err("native display decision exceeds its bound or lacks correlation".into());
        }
        attempt::Query::new(material, transaction, &dispatch, deadline)?;
        Ok(Self {
            material: material.into(),
            transaction: transaction.into(),
            dispatch,
            deadline,
            decision,
            protected_decision,
            confirm,
        })
    }

    pub(crate) fn validate_at(&self, now: u64) -> Result<(), String> {
        if now == 0 || self.deadline <= now || self.deadline - now > 15_000 {
            return Err("native display decision is outside its original deadline".into());
        }
        Ok(())
    }

    pub(crate) fn wire(&self) -> (&str, &str, String, u64, String, String, bool) {
        (
            &self.material,
            &self.transaction,
            self.dispatch.to_hex(),
            self.deadline,
            self.decision.to_hex(),
            self.protected_decision.to_hex(),
            self.confirm,
        )
    }
}

impl NativeSessionChannel {
    /// One continuation, no reconnection to recover continuation rights, no
    /// retry and no apply. The original native reservation must still belong
    /// to this owner invocation and connection. A phase never proves success.
    pub fn dispatch_display_continuation(
        &self,
        continuation: &NativeDisplayContinuation,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Executor)?;
        continuation.validate_at(unix_ms()?)?;
        let started = Instant::now();
        let boot = current_boot()?;
        let material = linura_core::DisplayLayoutMaterial::decode(&continuation.material)
            .map_err(|e| e.to_string())?;
        let owner = self.discover(material.lock().epoch().uid(), started)?;
        if material.lock().epoch().boot() != &boot
            || material.lock().security_owner_invocation() != &owner.invocation
        {
            return Err("native display decision belongs to a replaced owner or boot".into());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        continuation.validate_at(unix_ms()?)?;
        let query = (
            continuation.material.as_str(),
            continuation.transaction.as_str(),
            linura_provider_sdk::display_layout_effect(&continuation.material)?
                .digest()
                .to_hex(),
            continuation.dispatch.to_hex(),
            continuation.deadline,
        );
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "ContinuePreparedDisplay",
            &(
                query,
                continuation.decision.to_hex(),
                continuation.protected_decision.to_hex(),
                continuation.confirm,
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "u"
        {
            return Err("native display decision reply identity or signature differs".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native display decision reply is malformed")?;
        self.revalidate_observation(&owner, &boot, started)?;
        if !(2..=6).contains(&phase) {
            return Err("native display decision outcome is unavailable; no retry".into());
        }
        Ok(phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> NativeDisplayContinuation {
        let lock = super::super::tests::coverage(true).resource;
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = |x| format!("LNDL:1;{topology};1:2:enabled:1920:1080:59940:1250:0:{x}:0:-;");
        let material = format!("LNDI:1;{};{}{}", lock.as_str(), layout(0), layout(100));
        NativeDisplayContinuation::new(
            &material,
            "transaction:decision",
            ComponentDigest::from_bytes([1; 32]),
            25_000,
            ComponentDigest::from_bytes([2; 32]),
            ComponentDigest::from_bytes([3; 32]),
            true,
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    #[test]
    fn original_deadline_correlation_and_closed_material_are_required() {
        let good = fixture();
        assert!(good.validate_at(10_000).is_ok());
        for now in [0, 9_999, 25_000, 25_001, u64::MAX] {
            assert!(good.validate_at(now).is_err());
        }
        for which in 0..6 {
            let mut value = fixture();
            match which {
                0 => value.material.push('x'),
                1 => value.transaction = "transaction:UPPER".into(),
                2 => value.dispatch = ComponentDigest::from_bytes([0; 32]),
                3 => value.decision = ComponentDigest::from_bytes([0; 32]),
                4 => value.protected_decision = ComponentDigest::from_bytes([0; 32]),
                _ => value.deadline = 0,
            }
            assert!(
                NativeDisplayContinuation::new(
                    &value.material,
                    &value.transaction,
                    value.dispatch,
                    value.deadline,
                    value.decision,
                    value.protected_decision,
                    value.confirm
                )
                .is_err()
            );
        }
        let (material, transaction, dispatch, deadline, decision, protected, confirm) = good.wire();
        assert_eq!(material, good.material);
        assert_eq!(transaction, "transaction:decision");
        assert_eq!(deadline, 25_000);
        assert_eq!(dispatch, good.dispatch.to_hex());
        assert_eq!(decision, good.decision.to_hex());
        assert_eq!(protected, good.protected_decision.to_hex());
        assert!(confirm);
    }
}
