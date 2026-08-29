use std::collections::{BTreeMap, BTreeSet};

use crate::{
    EffectivePolicy, OperationPolicy, PolicyError, ProtocolSpec, RiskEvidenceAggregation,
    RiskEvidencePolicy, UnveilPath,
};

pub const DEFAULT_MAX_DEPTH: usize = 8;

#[derive(Default)]
pub struct PolicyRepository {
    specs: BTreeMap<String, ProtocolSpec>,
    max_depth: usize,
}

pub struct ResolveResult {
    pub policy: EffectivePolicy,
    pub expansion_audit: Vec<String>,
}

impl PolicyRepository {
    pub fn new(specs: impl IntoIterator<Item = ProtocolSpec>) -> Self {
        Self {
            specs: specs
                .into_iter()
                .map(|s| (s.protocol_id.clone(), s))
                .collect(),
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn resolve(&self, protocol_id: &str) -> Result<ResolveResult, PolicyError> {
        self.resolve_inner(protocol_id, &mut Vec::new())
    }

    fn resolve_inner(
        &self,
        protocol_id: &str,
        chain: &mut Vec<String>,
    ) -> Result<ResolveResult, PolicyError> {
        if let Some(position) = chain.iter().position(|p| p == protocol_id) {
            let mut cycle = chain[position..].to_vec();
            cycle.push(protocol_id.to_owned());
            return Err(PolicyError::Cycle(cycle.join(" -> ")));
        }
        if chain.len() >= self.max_depth {
            let mut full = chain.clone();
            full.push(protocol_id.to_owned());
            return Err(PolicyError::ExcessiveDepth {
                maximum: self.max_depth,
                chain: full.join(" -> "),
            });
        }
        let child = self
            .specs
            .get(protocol_id)
            .ok_or_else(|| PolicyError::MissingParent(protocol_id.to_owned()))?
            .clone();
        let Some(parent_id) = child.extends.clone() else {
            return Ok(ResolveResult {
                policy: child,
                expansion_audit: Vec::new(),
            });
        };
        chain.push(protocol_id.to_owned());
        let parent_result = self.resolve_inner(&parent_id, chain)?;
        chain.pop();
        merge(parent_result, child)
    }
}

fn approved(child: &ProtocolSpec) -> bool {
    child.privilege_expansion.as_ref().is_some_and(|a| {
        a.approved && !a.approval_id.trim().is_empty() && !a.reason.trim().is_empty()
    })
}

fn merge(mut parent: ResolveResult, mut child: ProtocolSpec) -> Result<ResolveResult, PolicyError> {
    let allow_expansion = approved(&child);
    merge_risk_evidence(
        parent.policy.risk_evidence.as_ref(),
        &mut child.risk_evidence,
        allow_expansion,
        &mut parent.expansion_audit,
    )?;
    let parent_promises: BTreeSet<_> = parent
        .policy
        .process_constraints
        .pledge_promises
        .iter()
        .cloned()
        .collect();
    let child_promises: BTreeSet<_> = child
        .process_constraints
        .pledge_promises
        .iter()
        .cloned()
        .collect();
    let extra: Vec<_> = child_promises
        .difference(&parent_promises)
        .cloned()
        .collect();
    if !extra.is_empty() && !allow_expansion {
        return Err(PolicyError::PrivilegeExpansion {
            path: "/process_constraints/pledge_promises".into(),
            detail: extra.join(","),
        });
    }
    if !extra.is_empty() {
        parent
            .expansion_audit
            .push(format!("pledge_promises:+{}", extra.join(",")));
    }

    let parent_paths: BTreeMap<_, _> = parent
        .policy
        .process_constraints
        .unveil_paths
        .iter()
        .map(|p| (p.path.clone(), p.permissions.clone()))
        .collect();
    for path in &child.process_constraints.unveil_paths {
        match parent_paths.get(&path.path) {
            None if !allow_expansion => {
                return Err(PolicyError::PrivilegeExpansion {
                    path: "/process_constraints/unveil_paths".into(),
                    detail: path.path.clone(),
                });
            }
            None => parent
                .expansion_audit
                .push(format!("unveil_paths:+{}", path.path)),
            Some(parent_permissions)
                if !permission_subset(&path.permissions, parent_permissions)
                    && !allow_expansion =>
            {
                return Err(PolicyError::PrivilegeExpansion {
                    path: format!("/process_constraints/unveil_paths/{}", path.path),
                    detail: format!("{} -> {}", parent_permissions, path.permissions),
                });
            }
            _ => {}
        }
    }

    let parent_ops: BTreeMap<_, _> = parent
        .policy
        .operations
        .iter()
        .map(|o| (o.name.clone(), o.clone()))
        .collect();
    let mut operations = Vec::new();
    for operation in &child.operations {
        if let Some(parent_operation) = parent_ops.get(&operation.name) {
            check_operation(
                parent_operation,
                operation,
                allow_expansion,
                &mut parent.expansion_audit,
            )?;
        } else if !allow_expansion {
            return Err(PolicyError::PrivilegeExpansion {
                path: "/operations".into(),
                detail: operation.name.clone(),
            });
        } else {
            parent
                .expansion_audit
                .push(format!("operations:+{}", operation.name));
        }
        operations.push(operation.clone());
    }
    for parent_operation in &parent.policy.operations {
        if !operations.iter().any(|o| o.name == parent_operation.name) {
            operations.push(parent_operation.clone());
        }
    }

    if child.data_constraints.input_schema != parent.policy.data_constraints.input_schema {
        return Err(PolicyError::Conflict {
            path: "/data_constraints/input_schema".into(),
            detail: "schema override is ambiguous".into(),
        });
    }
    if let (Some(parent_network), Some(child_network)) =
        (&parent.policy.network_policy, &child.network_policy)
    {
        let parent_inbound: BTreeSet<_> = parent_network.inbound.iter().cloned().collect();
        let parent_outbound: BTreeSet<_> = parent_network.outbound.iter().cloned().collect();
        let child_inbound: BTreeSet<_> = child_network.inbound.iter().cloned().collect();
        let child_outbound: BTreeSet<_> = child_network.outbound.iter().cloned().collect();
        let expanded: Vec<_> = child_inbound
            .difference(&parent_inbound)
            .chain(child_outbound.difference(&parent_outbound))
            .cloned()
            .collect();
        let enables_dns = child_network.dns_enabled && !parent_network.dns_enabled;
        if (!expanded.is_empty() || enables_dns) && !allow_expansion {
            return Err(PolicyError::PrivilegeExpansion {
                path: "/network_policy".into(),
                detail: "network access expanded".into(),
            });
        }
        if !expanded.is_empty() || enables_dns {
            parent
                .expansion_audit
                .push("network_policy:expanded".into());
        }
    } else if child.network_policy.is_some()
        && parent.policy.network_policy.is_none()
        && !allow_expansion
    {
        return Err(PolicyError::PrivilegeExpansion {
            path: "/network_policy".into(),
            detail: "network policy added".into(),
        });
    }
    child.operations = operations;
    child.process_constraints.pledge_promises = parent_promises
        .intersection(&child_promises)
        .cloned()
        .collect();
    if allow_expansion {
        child.process_constraints.pledge_promises.extend(extra);
    }
    child.data_constraints.maximum_message_bytes = child
        .data_constraints
        .maximum_message_bytes
        .min(parent.policy.data_constraints.maximum_message_bytes);
    child.data_constraints.maximum_nesting_depth = child
        .data_constraints
        .maximum_nesting_depth
        .min(parent.policy.data_constraints.maximum_nesting_depth);
    child.extends = None;
    child.privilege_expansion = None;
    Ok(ResolveResult {
        policy: child,
        expansion_audit: parent.expansion_audit,
    })
}

fn merge_risk_evidence(
    parent: Option<&RiskEvidencePolicy>,
    child: &mut Option<RiskEvidencePolicy>,
    allow_expansion: bool,
    audit: &mut Vec<String>,
) -> Result<(), PolicyError> {
    let Some(parent) = parent else { return Ok(()) };
    let Some(child_policy) = child.as_ref() else {
        *child = Some(parent.clone());
        return Ok(());
    };
    let weakened = (parent.enabled && !child_policy.enabled)
        || child_policy.minimum_occurrences < parent.minimum_occurrences
        || child_policy.minimum_severity_bps < parent.minimum_severity_bps
        || child_policy.minimum_confidence_bps < parent.minimum_confidence_bps
        || matches!(parent.aggregation, RiskEvidenceAggregation::AllThresholds)
            && matches!(
                child_policy.aggregation,
                RiskEvidenceAggregation::AnyThreshold
            );
    if weakened && !allow_expansion {
        return Err(PolicyError::PrivilegeExpansion {
            path: "/risk_evidence".into(),
            detail: "RiskEvidence quarantine policy weakened or disabled".into(),
        });
    }
    if weakened {
        audit.push("risk_evidence:weakened".into());
    }
    Ok(())
}

fn permission_subset(child: &str, parent: &str) -> bool {
    child.chars().all(|c| parent.contains(c))
}

fn check_operation(
    parent: &OperationPolicy,
    child: &OperationPolicy,
    allow: bool,
    audit: &mut Vec<String>,
) -> Result<(), PolicyError> {
    let p_context: BTreeSet<_> = parent.required_context.iter().collect();
    let c_context: BTreeSet<_> = child.required_context.iter().collect();
    if !p_context.is_subset(&c_context) {
        return Err(PolicyError::PrivilegeExpansion {
            path: format!("/operations/{}/required_context", child.name),
            detail: "required context removed".into(),
        });
    }
    let p_actors: BTreeSet<_> = parent.allowed_actors.iter().collect();
    let c_actors: BTreeSet<_> = child.allowed_actors.iter().collect();
    let extra: Vec<_> = c_actors
        .difference(&p_actors)
        .map(|s| (*s).clone())
        .collect();
    if !extra.is_empty() && !allow {
        return Err(PolicyError::PrivilegeExpansion {
            path: format!("/operations/{}/allowed_actors", child.name),
            detail: extra.join(","),
        });
    }
    if !extra.is_empty() {
        audit.push(format!(
            "operations/{}/allowed_actors:+{}",
            child.name,
            extra.join(",")
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn _type_anchor(_: UnveilPath) {}
