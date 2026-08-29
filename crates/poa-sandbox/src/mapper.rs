use std::collections::BTreeMap;
use std::path::{Component, Path};

use poa_protocol::{ProcessConstraints, UnveilPath};

use crate::EnforcementError;

pub fn pledge_string(policy: &ProcessConstraints) -> Result<String, EnforcementError> {
    let mut promises = policy.pledge_promises.clone();
    promises.sort();
    promises.dedup();
    if promises
        .iter()
        .any(|p| p.is_empty() || p.contains(char::is_whitespace))
    {
        return Err(EnforcementError::InvalidPolicy(
            "invalid pledge promise".into(),
        ));
    }
    Ok(promises.join(" "))
}

pub fn normalized_unveil(policy: &ProcessConstraints) -> Result<Vec<UnveilPath>, EnforcementError> {
    let mut paths = BTreeMap::<String, String>::new();
    for item in &policy.unveil_paths {
        let path = Path::new(&item.path);
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(EnforcementError::InvalidPolicy(format!(
                "non-normalized unveil path: {}",
                item.path
            )));
        }
        let normalized = path.to_string_lossy().to_string();
        if let Some(existing) = paths.insert(normalized.clone(), item.permissions.clone())
            && existing != item.permissions
        {
            return Err(EnforcementError::InvalidPolicy(format!(
                "conflicting permissions for {normalized}"
            )));
        }
    }
    Ok(paths
        .into_iter()
        .map(|(path, permissions)| UnveilPath { path, permissions })
        .collect())
}

/// Builds the actual OpenBSD kernel call plan. `unveil(NULL, NULL)` alone
/// leaves the filesystem unrestricted when no paths were unveiled, so an
/// empty policy first masks the root with an empty permission set.
pub fn unveil_plan(policy: &ProcessConstraints) -> Result<Vec<UnveilPath>, EnforcementError> {
    let paths = normalized_unveil(policy)?;
    if paths.is_empty() {
        Ok(vec![UnveilPath {
            path: "/".into(),
            permissions: String::new(),
        }])
    } else {
        Ok(paths)
    }
}
