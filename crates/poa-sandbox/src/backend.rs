use poa_protocol::{EffectivePolicy, ProcessConstraints};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("unsupported platform or feature: {0}")]
    Unsupported(String),
    #[error("invalid enforcement policy: {0}")]
    InvalidPolicy(String),
    #[error("resource preparation failed: {0}")]
    Resource(String),
    #[error("unveil failed for {path}: errno={errno}")]
    Unveil { path: String, errno: i32 },
    #[error("unveil lock failed: errno={0}")]
    UnveilLock(i32),
    #[error("pledge failed: errno={0}")]
    Pledge(i32),
}

pub trait ProcessConstraintBackend {
    fn name(&self) -> &'static str;
    fn validate_policy(&self, policy: &EffectivePolicy) -> Result<(), EnforcementError>;
    fn prepare_resources(&self, policy: &EffectivePolicy) -> Result<(), EnforcementError>;
    fn apply_filesystem_constraints(
        &self,
        policy: &ProcessConstraints,
    ) -> Result<(), EnforcementError>;
    fn apply_process_constraints(
        &self,
        policy: &ProcessConstraints,
    ) -> Result<(), EnforcementError>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StartupEnforcement {
    pub resources_prepared: bool,
    pub listener_initialized: bool,
    pub filesystem_applied: bool,
    pub process_applied: bool,
    pub business_loop_entered: bool,
}

impl StartupEnforcement {
    pub fn prepare(
        &mut self,
        backend: &dyn ProcessConstraintBackend,
        policy: &EffectivePolicy,
    ) -> Result<(), EnforcementError> {
        backend.validate_policy(policy)?;
        backend.prepare_resources(policy)?;
        self.resources_prepared = true;
        Ok(())
    }

    pub fn enforce_after_listener(
        &mut self,
        backend: &dyn ProcessConstraintBackend,
        policy: &EffectivePolicy,
    ) -> Result<(), EnforcementError> {
        if !self.resources_prepared {
            return Err(EnforcementError::Resource(
                "resources must be prepared before listener initialization".into(),
            ));
        }
        if !self.listener_initialized {
            return Err(EnforcementError::Resource(
                "listener must be initialized before sandbox".into(),
            ));
        }
        backend.apply_filesystem_constraints(&policy.process_constraints)?;
        self.filesystem_applied = true;
        backend.apply_process_constraints(&policy.process_constraints)?;
        self.process_applied = true;
        self.business_loop_entered = true;
        Ok(())
    }
}
