//! Historical kept intent survives loss of every old native/Root handle. It is
//! deliberately a different type from a current adoption inspection: there is
//! no current observation, approval, peer, lease or continuation in this value.
use super::*;
use linura_core::{DisplayLayout, DisplayLayoutMaterial, DisplayOrdinaryReleaseOutcome};

#[derive(Debug, Eq, PartialEq)]
pub struct RetainedOrdinaryDisplayKeptIntent {
    original: PlanDesiredStateRequest,
    material: CommittedStateMaterial,
    release: PlanDesiredStateRequest,
    release_material: CommittedStateMaterial,
    desired: DisplayLayout,
    released: ContentDigest,
    adopted: ContentDigest,
    state: ContentDigest,
}
impl RetainedOrdinaryDisplayKeptIntent {
    pub const fn original_request(&self) -> &PlanDesiredStateRequest {
        &self.original
    }
    pub const fn material(&self) -> &CommittedStateMaterial {
        &self.material
    }
    pub const fn release_request(&self) -> &PlanDesiredStateRequest {
        &self.release
    }
    pub const fn release_material(&self) -> &CommittedStateMaterial {
        &self.release_material
    }
    /// Historical desired state, not an observation of current scanout.
    pub const fn desired_layout(&self) -> &DisplayLayout {
        &self.desired
    }
    pub const fn released_record(&self) -> &ContentDigest {
        &self.released
    }
    pub const fn adopted_record(&self) -> &ContentDigest {
        &self.adopted
    }
    pub const fn state_record(&self) -> &ContentDigest {
        &self.state
    }

    /// Proposal only, including after the old peers have disappeared. The new
    /// baseline, mapping, capabilities and lock must independently be obtained
    /// and revalidated by the replacement's canonical managed path. This value
    /// cannot stand in for that path or authorize reference/artifact retirement.
    pub fn replacement_layout_candidate(
        &self,
        mapping: &linura_core::DisplayRecoveryMapping,
        current: DisplayLayout,
        capabilities: &[linura_core::NativeOutputCapabilities],
        lock: SessionLockId,
    ) -> Result<linura_core::DisplayLayoutIntent, ManagedLifecycleError> {
        mapping
            .desired_state_candidate(&self.desired, current, capabilities, lock)
            .map_err(|_| invalid_original())
    }
}

fn component(raw: &str) -> Result<(), ManagedLifecycleError> {
    let d = ComponentDigest::parse_hex(raw).map_err(|_| invalid_original())?;
    if d == ComponentDigest::from_bytes([0; 32]) || d.to_hex() != raw {
        return Err(invalid_original());
    }
    Ok(())
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Recover only approved structured kept intent and its complete retained
    /// Control completion ancestry. Root record digests remain historical
    /// correlations. Old providers are neither called nor reconstructed.
    /// This read cannot admit a replacement, retire references or delete files.
    pub fn retained_ordinary_display_kept_intent(
        &self,
        principal: AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<RetainedOrdinaryDisplayKeptIntent, ManagedLifecycleError> {
        let checked = self.checked_display_history()?;
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let row = self
            .display_journal()?
            .load(&pid, request_id)
            .map_err(|_| invalid_original())?;
        if row.principal() != &pid || row.request_id() != request_id {
            return Err(invalid_original());
        }
        let release = crate::retained_request::decode(&row)?;
        validate_public_request(&release)?;
        validate_request_identity(&release)?;
        if row.digest() != &crate::durable_authority::digest_request(&release)? {
            return Err(invalid_original());
        }
        let intent = crate::display_ordinary_release_intent::OrdinaryReleaseIntent::load(
            self.display_journal()?,
            &pid,
            &release,
        )?;
        intent.require_claim(self.display_journal()?, &pid, &release)?;
        let ordinary = linura_core::DisplayOrdinaryReleaseMaterial::decode(intent.material())
            .map_err(|_| invalid_original())?;
        if ordinary.outcome() != DisplayOrdinaryReleaseOutcome::Keep
            || principal.as_str()
                != format!(
                    "unix:uid:{}",
                    ordinary.original().topology().session().uid()
                )
        {
            return Err(invalid_original());
        }
        let original =
            checked.original_request(&principal, &ordinary.lineage().original_request)?;
        let history =
            self.ordinary_release_history_checked(&checked, &principal, &original.request_id)?;
        let original_material = self
            .authority
            .display_committed_material(&principal, &original)?;
        let release_material = self
            .authority
            .display_committed_material(&principal, &release)?;
        let l = ordinary.lineage();
        if original != history.request
            || original_material.snapshot != history.snapshot
            || original.desired_state.get("layout").map(String::as_str)
                != Some(ordinary.original_text())
            || history.restored
            || l.original_dispatch != history.dispatch_digest
            || l.terminal_record != history.terminal_digest.hex()
            || l.signed_binding != original_material.snapshot.binding_digest.hex()
            || l.generation != original_material.snapshot.current_generation
            || l.state_version != original_material.snapshot.state_version
        {
            return Err(invalid_original());
        }
        let original_intent = DisplayLayoutMaterial::decode(ordinary.original_text())
            .map_err(|_| invalid_original())?
            .validate_native(
                history.checkpoint.historical_facts.inventory(),
                history.checkpoint.historical_facts.capabilities(),
            )
            .map_err(|_| invalid_original())?;
        let metadata = history
            .checkpoint
            .historical_facts
            .recovery_metadata()
            .ok_or_else(invalid_original)?
            .iter()
            .map(|(output, old)| {
                linura_observation::DisplayRecoveryMetadata::new(
                    true,
                    old.base_configuration_digest().into(),
                    old.native_identity_digest().into(),
                )
                .map(|metadata| (output.clone(), metadata))
                .map_err(|_| invalid_original())
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if linura_provider_sdk::display_layout_source_guard(original_intent.desired(), &metadata)
            .map_err(|_| invalid_original())?
            .to_hex()
            != l.current_source_guard
        {
            return Err(invalid_original());
        }
        let semantics = self.ordinary_adopted_semantics_checked(
            &checked,
            &principal,
            &release,
            original_intent.desired(),
        )?;
        if semantics.original != original || semantics.kept.as_ref() != Some(&original_material) {
            return Err(invalid_original());
        }
        let load = |kind| Entry::load(self.display_journal()?, kind, &pid, &release);
        let ready = load(Kind::Ready)?;
        let verified = load(Kind::Verified)?;
        let committed = load(Kind::Committed)?;
        let native_prepared = load(Kind::NativePrepared)?;
        let native_verified = load(Kind::NativeVerified)?;
        let final_prepared = load(Kind::FinalPrepared)?;
        let final_verified = load(Kind::FinalVerified)?;
        let released = load(Kind::Released)?;
        let adopted = load(Kind::Adopted)?;
        let state = load(Kind::AdoptedState)?;
        let snapshot = &release_material.snapshot;
        let receipt = self.ordinary_release_receipt(&principal, &release)?;
        let now = now_ms()?;
        // These times are historical ordering constraints. Expired evidence is
        // not renewed or returned as a current observation by this API.
        let times = [
            number(&ready.fields[11])?,
            number(&committed.fields[10])?,
            number(&native_prepared.fields[8])?,
            number(&native_verified.fields[7])?,
            number(&final_prepared.fields[10])?,
            number(&final_verified.fields[13])?,
            number(&released.fields[9])?,
            number(&adopted.fields[14])?,
        ];
        if times.iter().any(|t| *t == 0 || *t > now)
            || times.windows(2).any(|pair| pair[1] < pair[0])
            || number(&ready.fields[5])? != snapshot.current_generation
            || number(&ready.fields[6])?.checked_add(2) != Some(snapshot.state_version)
            || digest(&ready.fields[7])? != snapshot.binding_digest
            || Some(ready.fields[8].as_str()) != receipt.dispatch_digest.as_deref()
            || digest(&verified.fields[5])? != ready.digest()
            || number(&verified.fields[6])?.checked_add(1) != Some(snapshot.state_version)
            || digest(&verified.fields[7])? != release_material.desired_state_digest
            || digest(&verified.fields[8])? != release_material.graph_digest
            || digest(&verified.fields[9])? != release_material.provenance_digest
            || digest(&committed.fields[5])? != ready.digest()
            || digest(&committed.fields[6])? != verified.digest()
            || number(&committed.fields[7])? != snapshot.state_version
            || ready.fields[10] != committed.fields[8]
            || digest(&native_prepared.fields[5])? != committed.digest()
            || native_prepared.fields[6] != committed.fields[8]
            || digest(&native_verified.fields[5])? != native_prepared.digest()
            || digest(&final_prepared.fields[5])? != committed.digest()
            || digest(&final_prepared.fields[6])? != native_verified.digest()
            || final_prepared.fields[7] != native_verified.fields[6]
            || digest(&final_verified.fields[5])? != final_prepared.digest()
            || digest(&final_verified.fields[6])? != native_verified.digest()
            || digest(&released.fields[5])? != final_prepared.digest()
            || digest(&released.fields[6])? != final_verified.digest()
            || released.fields[7] != final_verified.fields[7]
            || digest(&adopted.fields[5])? != released.digest()
            || adopted.fields[6] != released.fields[8]
            || digest(&adopted.fields[7])? != final_verified.digest()
            || digest(&adopted.fields[8])? != release_material.desired_state_digest
            || digest(&adopted.fields[9])? != release_material.graph_digest
            || digest(&adopted.fields[10])? != release_material.provenance_digest
            || digest(&adopted.fields[11])? != snapshot.binding_digest
            || number(&adopted.fields[12])? != snapshot.current_generation
            || number(&adopted.fields[13])? != snapshot.state_version
            || state.fields[5..] != semantics.fields(adopted.digest())?
        {
            return Err(invalid_original());
        }
        for raw in [
            &ready.fields[8],
            &ready.fields[10],
            &native_verified.fields[6],
            &final_verified.fields[7],
            &released.fields[8],
        ] {
            component(raw)?;
        }
        for raw in [
            &ready.fields[9],
            &committed.fields[9],
            &native_prepared.fields[7],
            &final_prepared.fields[8],
            &final_verified.fields[8],
        ] {
            digest(raw)?;
        }
        for (first, expiry) in [
            (times[2], number(&native_prepared.fields[9])?),
            (times[4], number(&final_prepared.fields[9])?),
        ] {
            if expiry
                .checked_sub(first)
                .is_none_or(|span| span == 0 || span > 2000)
            {
                return Err(invalid_original());
            }
        }
        let window = linura_observation::DisplayNativeHandoffWindow {
            observed_unix_ms: number(&final_verified.fields[9])?,
            observed_boot_ms: number(&final_verified.fields[10])?,
            deadline_unix_ms: number(&final_verified.fields[11])?,
            deadline_boot_ms: number(&final_verified.fields[12])?,
        };
        window.valid_for_ms().map_err(|_| invalid_original())?;
        if window.observed_unix_ms < times[4] || window.observed_unix_ms > times[5] {
            return Err(invalid_original());
        }
        Ok(RetainedOrdinaryDisplayKeptIntent {
            original,
            material: original_material,
            release,
            release_material,
            desired: original_intent.desired().clone(),
            released: released.digest(),
            adopted: adopted.digest(),
            state: state.digest(),
        })
    }
}
