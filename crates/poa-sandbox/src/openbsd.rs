#[cfg(target_os = "openbsd")]
use std::ffi::CString;

use poa_protocol::{EffectivePolicy, OsBackend, ProcessConstraints};

#[cfg(target_os = "openbsd")]
use crate::mapper::unveil_plan;
use crate::mapper::{normalized_unveil, pledge_string};
use crate::{EnforcementError, ProcessConstraintBackend};

#[derive(Debug, Default)]
pub struct OpenBsdBackend;

impl OpenBsdBackend {
    /// Applies the configured unveil rules without locking the unveil table.
    /// This split is used by the OpenBSD startup instrumentation; normal
    /// enforcement still calls both phases through the backend trait.
    #[cfg(target_os = "openbsd")]
    pub fn apply_unveil_rules(&self, policy: &ProcessConstraints) -> Result<(), EnforcementError> {
        unsafe extern "C" {
            fn unveil(path: *const libc::c_char, permissions: *const libc::c_char) -> libc::c_int;
        }
        for item in unveil_plan(policy)? {
            let path = CString::new(item.path.clone())
                .map_err(|_| EnforcementError::InvalidPolicy("NUL in path".into()))?;
            let permissions = CString::new(item.permissions)
                .map_err(|_| EnforcementError::InvalidPolicy("NUL in permissions".into()))?;
            if unsafe { unveil(path.as_ptr(), permissions.as_ptr()) } != 0 {
                return Err(EnforcementError::Unveil {
                    path: item.path,
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                });
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "openbsd"))]
    pub fn apply_unveil_rules(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "OpenBSD unveil is unavailable on this host".into(),
        ))
    }

    #[cfg(target_os = "openbsd")]
    pub fn lock_unveil(&self) -> Result<(), EnforcementError> {
        unsafe extern "C" {
            fn unveil(path: *const libc::c_char, permissions: *const libc::c_char) -> libc::c_int;
        }
        if unsafe { unveil(std::ptr::null(), std::ptr::null()) } != 0 {
            return Err(EnforcementError::UnveilLock(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "openbsd"))]
    pub fn lock_unveil(&self) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "OpenBSD unveil is unavailable on this host".into(),
        ))
    }

    #[cfg(target_os = "openbsd")]
    pub fn apply_pledge(&self, policy: &ProcessConstraints) -> Result<(), EnforcementError> {
        unsafe extern "C" {
            fn pledge(
                promises: *const libc::c_char,
                execpromises: *const libc::c_char,
            ) -> libc::c_int;
        }
        let promises = CString::new(pledge_string(policy)?)
            .map_err(|_| EnforcementError::InvalidPolicy("NUL in promises".into()))?;
        if unsafe { pledge(promises.as_ptr(), std::ptr::null()) } != 0 {
            return Err(EnforcementError::Pledge(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "openbsd"))]
    pub fn apply_pledge(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "OpenBSD pledge is unavailable on this host".into(),
        ))
    }
}

impl ProcessConstraintBackend for OpenBsdBackend {
    fn name(&self) -> &'static str {
        "openbsd-pledge-unveil"
    }

    fn validate_policy(&self, policy: &EffectivePolicy) -> Result<(), EnforcementError> {
        if !matches!(policy.process_constraints.os_backend, OsBackend::Openbsd) {
            return Err(EnforcementError::InvalidPolicy(
                "OpenBSD backend requires os_backend=openbsd".into(),
            ));
        }
        normalized_unveil(&policy.process_constraints)?;
        pledge_string(&policy.process_constraints)?;
        if !policy.process_constraints.lock_after_initialization {
            return Err(EnforcementError::InvalidPolicy(
                "unveil lock is mandatory".into(),
            ));
        }
        Ok(())
    }

    fn prepare_resources(&self, policy: &EffectivePolicy) -> Result<(), EnforcementError> {
        for item in normalized_unveil(&policy.process_constraints)? {
            std::fs::metadata(&item.path).map_err(|error| {
                EnforcementError::Resource(format!(
                    "required unveil path {} is unavailable: {error}",
                    item.path
                ))
            })?;
        }
        Ok(())
    }

    #[cfg(target_os = "openbsd")]
    fn apply_filesystem_constraints(
        &self,
        policy: &ProcessConstraints,
    ) -> Result<(), EnforcementError> {
        self.apply_unveil_rules(policy)?;
        self.lock_unveil()
    }

    #[cfg(not(target_os = "openbsd"))]
    fn apply_filesystem_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "OpenBSD unveil is unavailable on this host".into(),
        ))
    }

    #[cfg(target_os = "openbsd")]
    fn apply_process_constraints(
        &self,
        policy: &ProcessConstraints,
    ) -> Result<(), EnforcementError> {
        self.apply_pledge(policy)
    }

    #[cfg(not(target_os = "openbsd"))]
    fn apply_process_constraints(&self, _: &ProcessConstraints) -> Result<(), EnforcementError> {
        Err(EnforcementError::Unsupported(
            "OpenBSD pledge is unavailable on this host".into(),
        ))
    }
}
