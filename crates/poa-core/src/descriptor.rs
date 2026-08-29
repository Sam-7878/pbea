#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionDescriptor<A, S, C, O> {
    pub actor: A,
    pub asset: S,
    pub context: C,
    pub operation: O,
}
