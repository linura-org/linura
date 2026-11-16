//! Semantic state and release-protocol bookkeeping have separate identities.
//! These authenticated comparisons never reconstruct a review or effect permit.
use super::*;
use linura_core::{DisplayLayout, DisplayOrdinaryReleaseMaterial, DisplayOrdinaryReleaseOutcome};
use linura_transaction::{TransactionSnapshot, digest_bytes};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct AdoptedSemantics {
    pub(super) original: PlanDesiredStateRequest,
    pub(super) snapshot: TransactionSnapshot,
    pub(super) outcome: DisplayOrdinaryReleaseOutcome,
    pub(super) layout: DisplayLayout,
    pub(super) kept: Option<CommittedStateMaterial>,
}
impl AdoptedSemantics {
    pub(super) fn fields(
        &self,
        adopted: ContentDigest,
    ) -> Result<Vec<String>, ManagedLifecycleError> {
        let layout = self
            .layout
            .canonical_text()
            .map_err(|_| invalid_original())?;
        let mut fields = vec![
            adopted.as_str().into(),
            self.original.request_id.as_str().into(),
            crate::durable_authority::digest_request(&self.original)?
                .as_str()
                .into(),
            self.snapshot.transaction_id.as_str().into(),
            self.snapshot.current_generation.to_string(),
            self.snapshot.state_version.to_string(),
            self.snapshot.binding_digest.as_str().into(),
            digest_bytes("linura.display.adopted-layout.v1", layout.as_bytes())
                .as_str()
                .into(),
            self.outcome.as_str().into(),
        ];
        if let Some(kept) = &self.kept {
            fields.extend([
                kept.desired_state_digest.as_str().into(),
                kept.graph_digest.as_str().into(),
                kept.provenance_digest.as_str().into(),
            ]);
        } else {
            fields.extend(["none".into(), "none".into(), "none".into()]);
        }
        Ok(fields)
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn ordinary_adopted_semantics(
        &self,
        principal: &AuthenticatedPrincipal,
        release: &PlanDesiredStateRequest,
        layout: &DisplayLayout,
    ) -> Result<AdoptedSemantics, ManagedLifecycleError> {
        let checked = self.checked_display_history()?;
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let intent = crate::display_ordinary_release_intent::OrdinaryReleaseIntent::load(
            self.display_journal()?,
            &pid,
            release,
        )?;
        intent.require_claim(self.display_journal()?, &pid, release)?;
        let material = DisplayOrdinaryReleaseMaterial::decode(intent.material())
            .map_err(|_| invalid_original())?;
        let original = checked.original_request(principal, &material.lineage().original_request)?;
        let snapshot = self
            .authority
            .matching_request_snapshot(principal, &original)?;
        if original.desired_state.get("layout").map(String::as_str)
            != Some(material.original_text())
            || snapshot.binding_digest.hex() != material.lineage().signed_binding
            || snapshot.current_generation != material.lineage().generation
            || snapshot.state_version != material.lineage().state_version
            || layout.topology() != material.original().topology()
        {
            return Err(invalid_original());
        }
        // The caller supplies only the typed target of the full fresh native
        // inventory/session/lock/KMS join, not an arbitrary parsed layout.
        let kept = match material.outcome() {
            DisplayOrdinaryReleaseOutcome::Keep => {
                let kept = self
                    .authority
                    .display_committed_material(principal, &original)?;
                if kept.snapshot != snapshot {
                    return Err(invalid_original());
                }
                Some(kept)
            }
            DisplayOrdinaryReleaseOutcome::Revert | DisplayOrdinaryReleaseOutcome::Expired => {
                if snapshot.state != TransactionState::RecoveryBlocked {
                    return Err(invalid_original());
                }
                None
            }
        };
        Ok(AdoptedSemantics {
            original,
            snapshot,
            outcome: material.outcome(),
            layout: layout.clone(),
            kept,
        })
    }
}
