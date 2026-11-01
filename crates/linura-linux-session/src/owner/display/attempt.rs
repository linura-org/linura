//! Scoped compositor get_status, not dispatch or independent layout success.
use super::*;
use linura_core::{DisplayLayoutMaterial, ResourceId};
use linura_observation::ObservationAuthority;
use linura_provider_sdk::{ComponentDigest, display_layout_effect};

type AttemptWire = (String, String, String, u64, u64, u32, bool);

pub(super) struct Query<'a> {
    intent: DisplayLayoutMaterial<'a>,
    transaction: &'a str,
    dispatch: &'a ComponentDigest,
    effect: ComponentDigest,
    deadline: u64,
}
impl<'a> Query<'a> {
    pub(super) const fn material(&self) -> &DisplayLayoutMaterial<'a> {
        &self.intent
    }
    pub(super) const fn effect_digest(&self) -> ComponentDigest {
        self.effect
    }
    pub(super) fn new(
        material: &'a str,
        transaction: &'a str,
        dispatch: &'a ComponentDigest,
        deadline: u64,
    ) -> Result<Self, String> {
        if transaction.len() > 256
            || transaction.len() <= "transaction:".len()
            || !transaction.starts_with("transaction:")
            || !transaction
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'-'))
            || dispatch == &ComponentDigest::from_bytes([0; 32])
            || deadline == 0
        {
            return Err("native display attempt correlation is malformed".into());
        }
        Ok(Self {
            intent: DisplayLayoutMaterial::decode(material).map_err(|e| e.to_string())?,
            transaction,
            dispatch,
            deadline,
            effect: display_layout_effect(material)?.digest(),
        })
    }
}

fn project_attempt(
    mut coverage: ObservationEnvelope,
    query: &Query<'_>,
    sample: &AttemptWire,
) -> Result<ObservationEnvelope, String> {
    if coverage.authority != ObservationAuthority::NativeApi
        || coverage.resource
            != query
                .intent
                .lock()
                .resource_id()
                .map_err(|e| e.to_string())?
        || sample.0 != coverage.resource.as_str()
        || sample.1
            != query
                .intent
                .topology()
                .resource_id()
                .map_err(|e| e.to_string())?
                .as_str()
        || sample.2 != query.transaction
        || sample.3 != query.deadline
        || coverage.sequence == 0
    {
        return Err("native display attempt scope was replaced or substituted".into());
    }
    let phase = match sample.5 {
        2 => "pending",
        3 => "restoring",
        4 => "confirmed",
        5 => "restored",
        6 => "recovery-failed",
        7 => "absent",
        _ => return Err("native display attempt phase is unavailable or unsupported".into()),
    };
    coverage.provider = ProviderId::new(DISPLAY_PROVIDER).map_err(|e| e.to_string())?;
    coverage.resource = ResourceId::new(format!("display:attempt:{}", query.transaction))
        .map_err(|e| e.to_string())?;
    coverage.capability =
        CapabilityId::new("display.layout-attempt.observe").map_err(|e| e.to_string())?;
    coverage.attributes = BTreeMap::from([
        (
            "lock_resource".into(),
            ObservedValue::Text(sample.0.clone()),
        ),
        (
            "topology_resource".into(),
            ObservedValue::Text(sample.1.clone()),
        ),
        (
            "effect_digest".into(),
            ObservedValue::Text(query.effect.to_hex()),
        ),
        (
            "dispatch_digest".into(),
            ObservedValue::Text(query.dispatch.to_hex()),
        ),
        (
            "deadline_unix_ms".into(),
            ObservedValue::U64(query.deadline),
        ),
        ("state".into(), ObservedValue::Text(phase.into())),
    ]);
    Ok(coverage)
}

impl NativeSessionChannel {
    /// One attested read on the owner's original compositor connection. Neither
    /// a native terminal flag nor absence proves layout success or safe replay.
    pub fn observe_display_attempt(
        &self,
        material: &str,
        transaction: &str,
        dispatch_digest: &ComponentDigest,
        deadline_unix_ms: u64,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        let query = Query::new(material, transaction, dispatch_digest, deadline_unix_ms)?;
        let started = Instant::now();
        let boot = current_boot()?;
        let owner = self.discover(query.intent.lock().epoch().uid(), started)?;
        let wire = (
            material,
            transaction,
            query.effect.to_hex(),
            dispatch_digest.to_hex(),
            deadline_unix_ms,
        );
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveDisplayAttempt",
            &(wire,),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply.body().signature().to_string() != "(sssttub)" {
            return Err("native display attempt observation signature mismatch".into());
        }
        let (sample,): (AttemptWire,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native display attempt observation codec mismatch")?;
        if sample.0.len() > 256 || sample.1.len() > 256 || sample.2.len() > 256 {
            return Err("native display attempt observation exceeds its bound".into());
        }
        self.revalidate_observation(&owner, &boot, started)?;
        let coverage = observation(
            &owner,
            &boot,
            &sample.0,
            sample.6,
            sample.4,
            boot_ms()?,
            unix_ms()?,
            sequence,
        )?;
        let projected = project_attempt(coverage, &query, &sample)?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET {
            return Err("native display attempt exceeded its original probe deadline".into());
        }
        projected
            .require_current(unix_ms()?)
            .map_err(|e| e.to_string())?;
        Ok(projected)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::coverage;
    use super::*;

    fn value<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (String, AttemptWire, ComponentDigest) {
        let lock = coverage(true).resource;
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = |x| format!("LNDL:1;{topology};1:2:enabled:1920:1080:59940:1250:0:{x}:0:-;");
        let material = format!("LNDI:1;{};{}{}", lock.as_str(), layout(0), layout(100));
        (
            material,
            (
                lock.as_str().into(),
                topology.into(),
                "transaction:display-test".into(),
                15000,
                100,
                2,
                true,
            ),
            ComponentDigest::from_bytes([9; 32]),
        )
    }

    #[test]
    fn native_phases_project_closed_attempt_facts_without_asserting_layout_success() {
        let (material, mut sample, dispatch) = fixture();
        let query = value(Query::new(&material, &sample.2, &dispatch, sample.3));
        for (phase, expected) in [
            (2, "pending"),
            (3, "restoring"),
            (4, "confirmed"),
            (5, "restored"),
            (6, "recovery-failed"),
            (7, "absent"),
        ] {
            sample.5 = phase;
            let actual = value(project_attempt(coverage(true), &query, &sample));
            assert_eq!(actual.attributes.len(), 6);
            assert_eq!(
                actual.attributes.get("state"),
                Some(&ObservedValue::Text(expected.into()))
            );
            assert_eq!(actual.capability.as_str(), "display.layout-attempt.observe");
            assert_eq!(
                actual.resource.as_str(),
                "display:attempt:transaction:display-test"
            );
            assert_eq!(actual.observed_at_unix_ms, 10000);
            assert_eq!(actual.valid_for_ms, 1999);
            assert!(!actual.attributes.contains_key("layout"));
            assert!(!actual.attributes.contains_key("secure"));
        }
        for unsupported in [0, 1, 8, 9, u32::MAX] {
            sample.5 = unsupported;
            assert!(project_attempt(coverage(true), &query, &sample).is_err());
        }
    }

    #[test]
    fn substituted_scope_zero_sequence_and_synthetic_evidence_are_rejected() {
        let (material, sample, dispatch) = fixture();
        let query = value(Query::new(&material, &sample.2, &dispatch, sample.3));
        for index in 0..4 {
            let mut changed = sample.clone();
            match index {
                0 => changed.0.push('x'),
                1 => changed.1.push('x'),
                2 => changed.2.push('x'),
                _ => changed.3 += 1,
            }
            assert!(project_attempt(coverage(true), &query, &changed).is_err());
        }
        let mut bad = coverage(true);
        bad.sequence = 0;
        assert!(project_attempt(bad, &query, &sample).is_err());
        let mut bad = coverage(true);
        bad.authority = ObservationAuthority::SyntheticTest;
        assert!(project_attempt(bad, &query, &sample).is_err());
        for transaction in [
            "transaction:",
            "transaction:alias\n",
            "transaction:UPPER",
            "other:scope",
        ] {
            assert!(Query::new(&material, transaction, &dispatch, sample.3).is_err());
        }
        assert!(
            Query::new(
                &material,
                &sample.2,
                &ComponentDigest::from_bytes([0; 32]),
                sample.3
            )
            .is_err()
        );
        assert!(Query::new(&material, &sample.2, &dispatch, 0).is_err());
        assert!(Query::new("not a canonical intent", &sample.2, &dispatch, sample.3).is_err());
    }
}
