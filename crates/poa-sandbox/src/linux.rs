use poa_protocol::{EffectivePolicy, ProcessConstraints};

use crate::{EnforcementError, ProcessConstraintBackend};

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl LinuxBackend {
    pub const FUTURE_MAPPINGS: &[&str] = &["seccomp", "Landlock", "AppArmor/SELinux(optional)"];
}

impl ProcessConstraintBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux-skeleton"
    }
    fn validate_policy(&self, _: &EffectivePolicy) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "Linux enforcement is a non-evaluated skeleton".into(),
        ))
    }
    fn prepare_resources(&self, _: &EffectivePolicy) -> Result<(), EnforcementError> {
        unreachable!()
    }
    fn apply_filesystem_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        unreachable!()
    }
    fn apply_process_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        unreachable!()
    }
}
