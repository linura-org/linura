//! Route purpose-separated predecessor comparisons through the same fresh
//! canonical Apply path. Neither adoption nor Committed opens ordinary Begin.
use super::*;
mod ordinary;
mod ownership;
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn successor_for_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<Option<DisplaySuccessorContext>, ManagedLifecycleError> {
        match (
            self.ordinary_successor_for_request(principal, request)?,
            self.restoration_successor_for_request(principal, request)?,
        ) {
            (Some(v), None) => Ok(Some(DisplaySuccessorContext::Ordinary(v))),
            (None, Some(v)) => Ok(Some(DisplaySuccessorContext::Restoration(v))),
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(ManagedLifecycleError::Authority(
                "display successor has conflicting predecessor purposes".into(),
            )),
        }
    }
    pub(super) fn require_successor_context(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        match context {
            DisplaySuccessorContext::Restoration(v) => {
                self.require_restoration_successor_context(principal, v)
            }
            DisplaySuccessorContext::Ordinary(v) => {
                self.require_ordinary_successor_context(principal, v)
            }
        }
    }
    pub(super) fn require_successor_root(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        match context {
            DisplaySuccessorContext::Restoration(v) => {
                self.require_restoration_successor_root(principal, v)
            }
            DisplaySuccessorContext::Ordinary(v) => {
                self.require_ordinary_successor_root(principal, v)
            }
        }
    }
    pub(super) fn retain_successor_claim(
        &mut self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        match context {
            DisplaySuccessorContext::Restoration(v) => {
                self.retain_restoration_successor_claim(principal, request, v)
            }
            DisplaySuccessorContext::Ordinary(v) => {
                self.retain_ordinary_successor_claim(principal, request, v)
            }
        }
    }
    pub(super) fn require_successor_claim(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        match context {
            DisplaySuccessorContext::Restoration(v) => {
                self.require_restoration_successor_claim(principal, request, v)
            }
            DisplaySuccessorContext::Ordinary(v) => {
                self.require_ordinary_successor_claim(principal, request, v)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_successor_transfer<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
        dispatched: &Record,
        guard: &ComponentDigest,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<(), ManagedLifecycleError> {
        match context {
            DisplaySuccessorContext::Restoration(v) => self.verify_restoration_successor_transfer(
                principal, request, v, dispatched, guard, port, verifier,
            ),
            DisplaySuccessorContext::Ordinary(v) => self.verify_ordinary_successor_transfer(
                principal, request, v, dispatched, guard, port, verifier,
            ),
        }
    }
}
