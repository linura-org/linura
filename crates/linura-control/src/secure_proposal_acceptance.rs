use linura_intent::IntentProposal;
use linura_library::{LocalLibrary, ProposalAcceptanceRecord};
use linura_transaction::TransactionAuthorityKey;

use crate::authority_clock::ControlAuthorityClock;
use crate::plan_preview::AuthenticatedPrincipal;
use crate::proposal_acceptance::{
    AcceptProposalRequest, ProposalAcceptanceControl as InnerProposalAcceptanceControl,
    ProposalAcceptanceControlError,
};
use crate::proposal_authority::ControlProposalAuthority;

/// Production-facing v0.8 proposal acceptance control.
///
/// The generic authority-source and clock traits are intentionally kept inside
/// `linura-control` for deterministic qualification. Public callers cannot pair
/// proposal acceptance with an arbitrary mock authority source or caller-chosen
/// wall clock: production acceptance requires the concrete serialized
/// `ControlProposalAuthority` and monotonic `ControlAuthorityClock`.
///
/// Construction requires a protected, persistent 256-bit transaction-authority
/// key. The same key must be provisioned across restarts; no ephemeral authority
/// is minted inside this API.
#[derive(Debug)]
pub struct ProposalAcceptanceControl {
    inner: InnerProposalAcceptanceControl,
}

impl ProposalAcceptanceControl {
    #[must_use]
    pub fn from_authority_key(key: TransactionAuthorityKey) -> Self {
        Self {
            inner: InnerProposalAcceptanceControl::from_authority_key(key),
        }
    }

    /// Provision the verifier half of this Control authority into a Library.
    /// This is idempotent for the same key and fails closed for a different key.
    /// Production composition performs this before exposing the Library to
    /// request-processing code.
    pub fn provision_library(
        &self,
        library: &mut LocalLibrary,
    ) -> Result<(), ProposalAcceptanceControlError> {
        self.inner.provision_library(library)
    }

    pub fn accept(
        &self,
        library: &mut LocalLibrary,
        principal: &AuthenticatedPrincipal,
        proposal: &IntentProposal,
        request: &AcceptProposalRequest,
        authority: &mut ControlProposalAuthority,
        clock: &mut ControlAuthorityClock,
    ) -> Result<ProposalAcceptanceRecord, ProposalAcceptanceControlError> {
        self.inner
            .accept(library, principal, proposal, request, authority, clock)
    }
}
