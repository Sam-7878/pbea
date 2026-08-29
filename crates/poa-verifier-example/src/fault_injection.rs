#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    AfterCandidateBeforeCommit,
}

pub const S7_FAULT_POINT: FaultPoint = FaultPoint::AfterCandidateBeforeCommit;
