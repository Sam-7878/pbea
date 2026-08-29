use crate::{
    AbortReason, QuarantinePolicy, RejectReason, TransitionDescriptor, TransitionFailure,
    TransitionOutcome, TransitionResult, classify_failure,
};

pub trait AacoHooks<A, S, C, O> {
    type Candidate;
    type State;

    fn authorize(&self, descriptor: &TransitionDescriptor<A, S, C, O>) -> Result<(), RejectReason>;
    fn validate(&self, descriptor: &TransitionDescriptor<A, S, C, O>) -> Result<(), RejectReason>;
    fn mutate_candidate(
        &mut self,
        descriptor: &TransitionDescriptor<A, S, C, O>,
    ) -> Result<Self::Candidate, AbortReason>;
    fn reconcile(&mut self, candidate: Self::Candidate) -> Result<(), AbortReason>;
    fn state(&self) -> &Self::State;
}

/// Optional AACO execution contract for typed, stage-independent failures.
/// Candidate reconciliation is read-only; only `commit` may publish it.
pub trait RiskAwareAacoHooks<A, S, C, O> {
    type Candidate;
    type State;

    fn authorize(
        &self,
        descriptor: &TransitionDescriptor<A, S, C, O>,
    ) -> Result<(), TransitionFailure>;
    fn validate(
        &self,
        descriptor: &TransitionDescriptor<A, S, C, O>,
    ) -> Result<(), TransitionFailure>;
    fn mutate_candidate(
        &mut self,
        descriptor: &TransitionDescriptor<A, S, C, O>,
    ) -> Result<Self::Candidate, TransitionFailure>;
    fn reconcile(&self, candidate: &Self::Candidate) -> Result<(), TransitionFailure>;
    fn commit(&mut self, candidate: Self::Candidate) -> Result<(), TransitionFailure>;
    fn state(&self) -> &Self::State;
}

pub fn execute_transition<H, A, S, C, O>(
    hooks: &mut H,
    descriptor: &TransitionDescriptor<A, S, C, O>,
) -> TransitionOutcome
where
    H: AacoHooks<A, S, C, O>,
{
    if let Err(reason) = hooks.authorize(descriptor) {
        return TransitionOutcome::Reject(reason);
    }
    if let Err(reason) = hooks.validate(descriptor) {
        return TransitionOutcome::Reject(reason);
    }
    let candidate = match hooks.mutate_candidate(descriptor) {
        Ok(candidate) => candidate,
        Err(reason) => return TransitionOutcome::Abort(reason),
    };
    match hooks.reconcile(candidate) {
        Ok(()) => TransitionOutcome::Commit,
        Err(reason) => TransitionOutcome::Abort(reason),
    }
}

pub fn execute_transition_with_risk<H, A, S, C, O>(
    hooks: &mut H,
    descriptor: &TransitionDescriptor<A, S, C, O>,
    policy: Option<&QuarantinePolicy>,
) -> TransitionResult
where
    H: RiskAwareAacoHooks<A, S, C, O>,
{
    if let Err(failure) = hooks.authorize(descriptor) {
        return classify_failure(failure, policy);
    }
    if let Err(failure) = hooks.validate(descriptor) {
        return classify_failure(failure, policy);
    }
    let candidate = match hooks.mutate_candidate(descriptor) {
        Ok(candidate) => candidate,
        Err(failure) => return classify_failure(failure, policy),
    };
    if let Err(failure) = hooks.reconcile(&candidate) {
        return classify_failure(failure, policy);
    }
    match hooks.commit(candidate) {
        Ok(()) => TransitionResult {
            outcome: TransitionOutcome::Commit,
            risk_assessment: None,
        },
        Err(failure) => classify_failure(failure, policy),
    }
}
