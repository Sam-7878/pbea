use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Component, Path};

use regex::Regex;
use serde_json::Value;
use thiserror::Error;

use crate::{DeploymentMode, OsBackend, ProtocolSpec};

const PLEDGE_PROMISES: &[&str] = &[
    "stdio", "rpath", "wpath", "cpath", "dpath", "tmppath", "inet", "unix", "dns", "proc", "exec",
    "id", "flock", "tty", "getpw", "sendfd", "recvfd", "fattr",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy JSON could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("policy JSON could not be parsed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema compilation failed: {0}")]
    Schema(String),
    #[error("policy validation failed: {0:?}")]
    Validation(Vec<ValidationIssue>),
    #[error("parent specification not found: {0}")]
    MissingParent(String),
    #[error("inheritance cycle: {0}")]
    Cycle(String),
    #[error("maximum inheritance depth {maximum} exceeded: {chain}")]
    ExcessiveDepth { maximum: usize, chain: String },
    #[error("privilege expansion rejected at {path}: {detail}")]
    PrivilegeExpansion { path: String, detail: String },
    #[error("policy conflict at {path}: {detail}")]
    Conflict { path: String, detail: String },
}

fn issue(code: &str, path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        code: code.into(),
        path: path.into(),
        message: message.into(),
    }
}

fn safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !p.is_absolute()
        && !p.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

pub fn validate_value(value: &Value, schema: &Value) -> Result<ProtocolSpec, PolicyError> {
    let validator =
        jsonschema::validator_for(schema).map_err(|e| PolicyError::Schema(e.to_string()))?;
    let mut issues: Vec<_> = validator
        .iter_errors(value)
        .map(|e| {
            issue(
                "schema_validation",
                e.instance_path.to_string(),
                e.to_string(),
            )
        })
        .collect();
    if !issues.is_empty() {
        issues.sort_by(|a, b| (&a.path, &a.message).cmp(&(&b.path, &b.message)));
        return Err(PolicyError::Validation(issues));
    }

    let spec: ProtocolSpec = serde_json::from_value(value.clone())?;
    let semver = Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$").unwrap();
    if spec.protocol_id.trim().is_empty() {
        issues.push(issue(
            "empty_protocol_id",
            "/protocol_id",
            "protocol_id must not be empty",
        ));
    }
    if !semver.is_match(&spec.version) {
        issues.push(issue(
            "invalid_semver",
            "/version",
            "version must be semantic versioning",
        ));
    }
    if matches!(spec.mode, DeploymentMode::Production)
        && matches!(spec.process_constraints.os_backend, OsBackend::Noop)
    {
        issues.push(issue(
            "noop_in_production",
            "/process_constraints/os_backend",
            "noop is development-only",
        ));
    }
    for (index, promise) in spec.process_constraints.pledge_promises.iter().enumerate() {
        if !PLEDGE_PROMISES.contains(&promise.as_str()) {
            issues.push(issue(
                "unsupported_pledge",
                format!("/process_constraints/pledge_promises/{index}"),
                promise,
            ));
        }
    }
    for (index, unveil) in spec.process_constraints.unveil_paths.iter().enumerate() {
        if !Path::new(&unveil.path).is_absolute() || unveil.path.split('/').any(|p| p == "..") {
            issues.push(issue(
                "invalid_unveil_path",
                format!("/process_constraints/unveil_paths/{index}/path"),
                "must be normalized absolute path without traversal",
            ));
        }
        if unveil.permissions.is_empty()
            || unveil
                .permissions
                .chars()
                .any(|c| !matches!(c, 'r' | 'w' | 'x' | 'c'))
        {
            issues.push(issue(
                "invalid_unveil_permission",
                format!("/process_constraints/unveil_paths/{index}/permissions"),
                &unveil.permissions,
            ));
        }
    }
    if !safe_relative(&spec.data_constraints.input_schema) {
        issues.push(issue(
            "invalid_schema_path",
            "/data_constraints/input_schema",
            "must be a traversal-free relative path",
        ));
    }
    if spec.data_constraints.maximum_message_bytes == 0
        || spec.data_constraints.maximum_message_bytes > 16 * 1024 * 1024
    {
        issues.push(issue(
            "invalid_message_size",
            "/data_constraints/maximum_message_bytes",
            "must be 1..=16777216",
        ));
    }
    if spec.data_constraints.maximum_nesting_depth == 0
        || spec.data_constraints.maximum_nesting_depth > 128
    {
        issues.push(issue(
            "invalid_nesting_depth",
            "/data_constraints/maximum_nesting_depth",
            "must be 1..=128",
        ));
    }
    let mut operation_names = BTreeSet::new();
    for (index, operation) in spec.operations.iter().enumerate() {
        if !operation_names.insert(&operation.name) {
            issues.push(issue(
                "duplicate_operation",
                format!("/operations/{index}/name"),
                &operation.name,
            ));
        }
    }
    let mut unveil_permissions = BTreeMap::new();
    for (index, unveil) in spec.process_constraints.unveil_paths.iter().enumerate() {
        if let Some(existing) = unveil_permissions.insert(&unveil.path, &unveil.permissions) {
            let message = if existing == &unveil.permissions {
                "duplicate unveil path"
            } else {
                "conflicting unveil permissions"
            };
            issues.push(issue(
                "duplicate_unveil_path",
                format!("/process_constraints/unveil_paths/{index}/path"),
                message,
            ));
        }
    }
    for (index, rule) in spec
        .network_policy
        .iter()
        .flat_map(|n| n.inbound.iter().chain(n.outbound.iter()))
        .enumerate()
    {
        if !matches!(rule.protocol.as_str(), "tcp" | "udp") {
            issues.push(issue(
                "invalid_network_protocol",
                format!("/network_policy/rules/{index}/protocol"),
                &rule.protocol,
            ));
        }
        if rule.address == "*" || rule.address.is_empty() {
            issues.push(issue(
                "wildcard_network_address",
                format!("/network_policy/rules/{index}/address"),
                "wildcards are not permitted",
            ));
        }
        if !valid_ip_or_cidr(&rule.address) && !rule.address.chars().any(char::is_alphabetic) {
            issues.push(issue(
                "invalid_network_address",
                format!("/network_policy/rules/{index}/address"),
                &rule.address,
            ));
        }
        if spec.network_policy.as_ref().is_some_and(|n| !n.dns_enabled)
            && rule.address.chars().any(char::is_alphabetic)
        {
            issues.push(issue(
                "dns_disabled",
                format!("/network_policy/rules/{index}/address"),
                "hostname requires dns_enabled",
            ));
        }
    }
    if issues.is_empty() {
        Ok(spec)
    } else {
        Err(PolicyError::Validation(issues))
    }
}

fn valid_ip_or_cidr(address: &str) -> bool {
    if address.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((ip, prefix)) = address.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if ip.is_ipv4() { 32 } else { 128 }
}
