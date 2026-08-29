use poa_protocol::{DeploymentMode, EffectivePolicy, ProcessConstraints};

use crate::{EnforcementError, ProcessConstraintBackend};

#[derive(Debug, Default)]
pub struct NoOpDevelopmentBackend;

impl ProcessConstraintBackend for NoOpDevelopmentBackend {
    fn name(&self) -> &'static str {
        "noop-development-UNSAFE"
    }

    fn validate_policy(&self, policy: &EffectivePolicy) -> Result<(), EnforcementError> {
        if matches!(policy.mode, DeploymentMode::Production) {
            return Err(EnforcementError::InvalidPolicy(
                "no-op backend is forbidden in production".into(),
            ));
        }
        eprintln!(
            "WARNING: no-op development backend provides no OS enforcement and is invalid as evaluation evidence"
        );
        Ok(())
    }

    fn prepare_resources(&self, _: &EffectivePolicy) -> Result<(), EnforcementError> {
        Ok(())
    }
    fn apply_filesystem_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Ok(())
    }
    fn apply_process_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Ok(())
    }
}
