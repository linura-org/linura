//! Bounded authenticated historical ownership; never a new effect authority.
//! The newest predecessor still requires its actual live Root/native release
//! and an independently reviewed Apply. Old completed transfers are ancestry.
use super::*;
use linura_transaction::TransactionSnapshot;

fn invalid() -> ManagedLifecycleError {
    release::original::invalid_original()
}
fn require_historical_transfer(
    fields: &[String],
    principal: &str,
    request: &str,
    request_digest: &linura_transaction::ContentDigest,
    dispatch: Option<&str>,
    now: u64,
) -> Result<(), ManagedLifecycleError> {
    if fields.len() != 10
        || fields[1] != principal
        || fields[2] != request
        || fields[3] != request_digest.as_str()
        || Some(fields[6].as_str()) != dispatch
        || release::current_records::number(&fields[9])? == 0
        || release::current_records::number(&fields[9])? > now
    {
        return Err(invalid());
    }
    for index in [4, 5, 6] {
        let digest = ComponentDigest::parse_hex(&fields[index]).map_err(|_| invalid())?;
        if digest.to_hex() != fields[index] || digest == ComponentDigest::from_bytes([0; 32]) {
            return Err(invalid());
        }
    }
    for index in [7, 8] {
        release::current_records::digest(&fields[index])?;
    }
    Ok(())
}

#[derive(Default)]
struct OwnershipClosure {
    owners: BTreeMap<TransactionId, TransactionSnapshot>,
    seen: BTreeSet<TransactionId>,
}
impl OwnershipClosure {
    fn include(
        &mut self,
        terminal: &TransactionSnapshot,
        intermediate: &TransactionSnapshot,
        original: &TransactionSnapshot,
    ) -> Result<(), ManagedLifecycleError> {
        if !self.seen.insert(terminal.transaction_id.clone()) || self.seen.len() > 32 {
            return Err(invalid());
        }
        for snapshot in [terminal, intermediate, original] {
            if snapshot.principal != terminal.principal {
                return Err(invalid());
            }
            if self
                .owners
                .insert(snapshot.transaction_id.clone(), snapshot.clone())
                .is_some_and(|old| old != *snapshot)
                || self.owners.len() > 32
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(in crate::managed_lifecycle::display) fn successor_ownership_closure(
        &self,
        context: &DisplaySuccessorContext,
    ) -> Result<BTreeMap<TransactionId, TransactionSnapshot>, ManagedLifecycleError> {
        let terminal = match context {
            DisplaySuccessorContext::Ordinary(v) => &v.terminal,
            DisplaySuccessorContext::Restoration(v) => &v.terminal,
        };
        let principal =
            AuthenticatedPrincipal::new(terminal.principal.as_str()).map_err(|_| invalid())?;
        let mut closure = OwnershipClosure::default();
        let mut current = context.clone();
        loop {
            self.require_successor_context(&principal, &current)?;
            let (terminal, intermediate, origin) = match &current {
                DisplaySuccessorContext::Ordinary(v) => (
                    &v.terminal,
                    &v.original,
                    self.retained_display_request(&principal, &v.original.request_id)?,
                ),
                DisplaySuccessorContext::Restoration(v) => (
                    &v.terminal,
                    &v.restoration,
                    self.restoration_successor_origin(&principal, v)?,
                ),
            };
            let original = self
                .authority
                .matching_request_snapshot(&principal, &origin)?;
            if !matches!(
                original.state,
                TransactionState::Committed | TransactionState::RecoveryBlocked
            ) {
                return Err(invalid());
            }
            closure.include(terminal, intermediate, &original)?;
            let Some(previous) = self.successor_for_request(&principal, &origin)? else {
                break;
            };
            // A prepared claim or signed Committed state cannot stand in for
            // the earlier independently joined Root/native transfer. The
            // immutable purpose-specific proof is checked against its exact
            // canonical request, dispatch and full predecessor claim again.
            let fields = match &previous {
                DisplaySuccessorContext::Ordinary(v) => {
                    self.ordinary_historical_successor_fields(&principal, &origin, v)?
                }
                DisplaySuccessorContext::Restoration(v) => {
                    self.restoration_historical_successor_fields(&principal, &origin, v)?
                }
            };
            let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
            let history = DisplayHistory::load(
                self.display_journal()?,
                &pid,
                &crate::durable_authority::digest_request(&origin)?,
                &original.transaction_id,
                original.state,
                now_ms()?,
            )?;
            let dispatched = history.dispatched.ok_or_else(invalid)?;
            require_historical_transfer(
                &fields,
                principal.as_str(),
                origin.request_id.as_str(),
                &crate::durable_authority::digest_request(&origin)?,
                dispatched.dispatch_digest.as_deref(),
                now_ms()?,
            )?;
            current = previous;
        }
        Ok(closure.owners)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: Debug>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn snapshot(id: usize) -> TransactionSnapshot {
        let principal = value(PrincipalId::new("unix:uid:1000"));
        let request_id = value(RequestId::new(format!(
            "request:v010:display-layout:ancestor-{id}"
        )));
        TransactionSnapshot {
            transaction_id: TransactionId::for_namespace(&principal, &request_id),
            principal,
            request_id,
            current_generation: 0,
            state_version: 9,
            state: TransactionState::Committed,
            binding_digest: linura_transaction::digest_bytes(
                "test.display.ancestor",
                b"signed fixture",
            ),
        }
    }
    #[test]
    fn full_ancestor_ownership_retains_exact_snapshots_and_refuses_conflict_cycles_or_exhaustion() {
        let mut closure = OwnershipClosure::default();
        for id in [6, 4, 2] {
            value(closure.include(&snapshot(id), &snapshot(id - 1), &snapshot(id - 1)));
        }
        assert_eq!(closure.owners.len(), 6);
        assert_eq!(
            closure.owners.get(&snapshot(1).transaction_id),
            Some(&snapshot(1))
        );
        assert!(!closure.owners.contains_key(&snapshot(7).transaction_id));
        assert!(
            closure
                .include(&snapshot(2), &snapshot(1), &snapshot(1))
                .is_err()
        );
        let mut other = snapshot(7);
        other.principal = value(PrincipalId::new("unix:uid:1001"));
        assert!(
            OwnershipClosure::default()
                .include(&snapshot(8), &other, &snapshot(9))
                .is_err()
        );
        let mut changed = snapshot(1);
        changed.state_version += 1;
        assert!(
            closure
                .include(&snapshot(10), &changed, &snapshot(11))
                .is_err()
        );
        let mut exhausted = OwnershipClosure::default();
        for id in 1..=32 {
            value(exhausted.include(&snapshot(id), &snapshot(id), &snapshot(id)));
        }
        assert!(
            exhausted
                .include(&snapshot(33), &snapshot(33), &snapshot(33))
                .is_err()
        );
    }
    #[test]
    fn missing_or_substituted_historical_proof_never_transfers_ownership() {
        let digest = linura_transaction::digest_bytes("test.display.ancestor", b"signed fixture");
        let fields = vec![
            "purpose checked by adapter".into(),
            "unix:uid:1000".into(),
            "request:ancestor".into(),
            digest.as_str().into(),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            linura_transaction::digest_bytes("test.root.observation", b"fixture")
                .as_str()
                .into(),
            linura_transaction::digest_bytes("test.native.observation", b"fixture")
                .as_str()
                .into(),
            "1000".into(),
        ];
        let dispatch = "4".repeat(64);
        let check = |fields: &[String], dispatch: Option<&str>| {
            require_historical_transfer(
                fields,
                "unix:uid:1000",
                "request:ancestor",
                &digest,
                dispatch,
                1001,
            )
        };
        value(check(&fields, Some(dispatch.as_str())));
        assert!(check(&fields, None).is_err());
        for size in 0..fields.len() {
            assert!(check(&fields[..size], Some(dispatch.as_str())).is_err());
        }
        for index in 1..10 {
            let mut changed = fields.clone();
            changed[index] = if index < 4 {
                "other".into()
            } else if index < 9 {
                "0".repeat(64)
            } else {
                "1002".into()
            };
            assert!(
                check(&changed, Some(dispatch.as_str())).is_err(),
                "field {index}"
            );
        }
        for time in ["0", "01", "-1", "18446744073709551616"] {
            let mut changed = fields.clone();
            changed[9] = time.into();
            assert!(check(&changed, Some(dispatch.as_str())).is_err());
        }
    }
}
