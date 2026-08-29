use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::Utc;
use poa_core::{
    AacoHooks, AbortReason, AuditRecord, BasisPoints, EvidenceAggregation, QuarantinePolicy,
    QuarantineReason, RejectReason, RiskModelError, TransitionDescriptor, TransitionOutcome,
    execute_transition,
};
use poa_protocol::{
    EffectivePolicy, EndpointRule, OperationPolicy, RiskEvidenceAggregation, RiskEvidencePolicy,
    canonicalize, policy_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod adversarial;
pub mod fault_injection;
pub mod mode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    pub request_id: String,
    pub expiry: i64,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPayload {
    pub amount: u64,
    pub currency: String,
    #[serde(default)]
    pub inject_internal_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRequest {
    pub actor: String,
    pub asset: String,
    pub context: RequestContext,
    pub operation: String,
    pub payload: PaymentPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainState {
    pub committed_assets: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustState {
    pub violations: BTreeMap<String, u32>,
    pub quarantined_actors: BTreeSet<String>,
}

#[derive(Debug)]
pub struct ProcessingResult {
    pub outcome: TransitionOutcome,
    pub audit: AuditRecord,
}

pub struct Verifier {
    policy: EffectivePolicy,
    digest: String,
    request_schema: Value,
    pub domain_state: DomainState,
    pub trust_state: TrustState,
}

impl Verifier {
    pub fn new(policy: EffectivePolicy, request_schema: Value) -> anyhow::Result<Self> {
        jsonschema::validator_for(&request_schema)
            .map_err(|e| anyhow::anyhow!("request schema: {e}"))?;
        let digest = policy_digest(&policy)?;
        Ok(Self {
            policy,
            digest,
            request_schema,
            domain_state: DomainState::default(),
            trust_state: TrustState::default(),
        })
    }

    pub fn policy_digest(&self) -> &str {
        &self.digest
    }

    pub fn process_bytes(&mut self, bytes: &[u8]) -> ProcessingResult {
        let fallback_id = uuid::Uuid::new_v4().to_string();
        let actor = extract_string(bytes, "actor").unwrap_or_else(|| "unknown".into());
        let operation = extract_string(bytes, "operation").unwrap_or_else(|| "unknown".into());
        let payload_hash = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let outcome = self.process_bytes_inner(bytes, &actor);
        let transition_id = serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|v| {
                v.pointer("/context/request_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or(fallback_id);
        let audit = AuditRecord {
            transition_id,
            protocol_id: self.policy.protocol_id.clone(),
            protocol_version: self.policy.version.clone(),
            policy_digest: self.digest.clone(),
            actor,
            operation,
            outcome: outcome.label().into(),
            timestamp: Utc::now(),
            payload_hash: Some(payload_hash),
            risk_evidence: None,
        };
        ProcessingResult { outcome, audit }
    }

    fn process_bytes_inner(&mut self, bytes: &[u8], actor_hint: &str) -> TransitionOutcome {
        if bytes.len() > self.policy.data_constraints.maximum_message_bytes as usize {
            return self.violation(
                actor_hint,
                RejectReason::InvalidInput("maximum_message_bytes exceeded".into()),
            );
        }
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => return self.violation(actor_hint, RejectReason::InvalidInput(e.to_string())),
        };
        if nesting_depth(&value) > self.policy.data_constraints.maximum_nesting_depth {
            return self.violation(
                actor_hint,
                RejectReason::InvalidInput("maximum nesting depth exceeded".into()),
            );
        }
        let validator = match jsonschema::validator_for(&self.request_schema) {
            Ok(v) => v,
            Err(e) => return TransitionOutcome::Abort(AbortReason::InternalFailure(e.to_string())),
        };
        if let Some(error) = validator.iter_errors(&value).next() {
            return self.violation(actor_hint, RejectReason::InvalidInput(error.to_string()));
        }
        let request: TransitionRequest = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(e) => return self.violation(actor_hint, RejectReason::InvalidInput(e.to_string())),
        };
        if request.context.policy_digest != self.digest {
            return self.violation(&request.actor, RejectReason::PolicyDigestMismatch);
        }
        let operation = match self
            .policy
            .operations
            .iter()
            .find(|o| o.name == request.operation)
        {
            Some(op) => op.clone(),
            None => return self.violation(&request.actor, RejectReason::DisallowedOperation),
        };
        if !operation.allowed_actors.contains(&request.actor) {
            return self.violation(&request.actor, RejectReason::DisallowedActor);
        }
        for required in &operation.required_context {
            if !context_present(&request.context, required) {
                return self.violation(
                    &request.actor,
                    RejectReason::MissingContext(required.clone()),
                );
            }
        }
        let descriptor = TransitionDescriptor {
            actor: request.actor.clone(),
            asset: request.asset.clone(),
            context: request.context.clone(),
            operation: request.operation.clone(),
        };
        let mut hooks = PaymentHooks {
            operation: &operation,
            request: &request,
            state: &mut self.domain_state,
        };
        execute_transition(&mut hooks, &descriptor)
    }

    fn violation(&mut self, actor: &str, reason: RejectReason) -> TransitionOutcome {
        let count = self
            .trust_state
            .violations
            .entry(actor.to_owned())
            .or_default();
        *count += 1;
        if *count >= self.policy.failure_policy.quarantine_threshold {
            self.trust_state.quarantined_actors.insert(actor.to_owned());
            TransitionOutcome::Quarantine(QuarantineReason::RepeatedPolicyViolation)
        } else {
            TransitionOutcome::Reject(reason)
        }
    }

    pub fn canonical_request(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let value: Value = serde_json::from_slice(bytes)?;
        // serde_json maps are emitted deterministically; accepted input is normalized before use.
        Ok(serde_json::to_vec(&value)?)
    }

    pub fn authorize_inbound(&self, source: IpAddr, port: u16, protocol: &str) -> bool {
        self.policy.network_policy.as_ref().is_none_or(|n| {
            n.inbound
                .iter()
                .any(|r| endpoint_matches(r, source, port, protocol))
        })
    }

    pub fn authorize_outbound(&self, destination: IpAddr, port: u16, protocol: &str) -> bool {
        self.policy.network_policy.as_ref().is_some_and(|n| {
            n.outbound
                .iter()
                .any(|r| endpoint_matches(r, destination, port, protocol))
        })
    }
}

fn endpoint_matches(rule: &EndpointRule, address: IpAddr, port: u16, protocol: &str) -> bool {
    rule.protocol == protocol && rule.port == port && address_matches(&rule.address, address)
}

fn address_matches(rule: &str, address: IpAddr) -> bool {
    if let Ok(exact) = rule.parse::<IpAddr>() {
        return exact == address;
    }
    let Some((network, prefix)) = rule.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<IpAddr>(), prefix.parse::<u8>()) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn context_present(context: &RequestContext, field: &str) -> bool {
    match field {
        "request_id" => !context.request_id.is_empty(),
        "expiry" => context.expiry > 0,
        "policy_digest" => !context.policy_digest.is_empty(),
        _ => false,
    }
}

fn nesting_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(nesting_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(nesting_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn extract_string(bytes: &[u8], field: &str) -> Option<String> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .get(field)?
        .as_str()
        .map(str::to_owned)
}

struct PaymentHooks<'a> {
    operation: &'a OperationPolicy,
    request: &'a TransitionRequest,
    state: &'a mut DomainState,
}

impl AacoHooks<String, String, RequestContext, String> for PaymentHooks<'_> {
    type Candidate = (String, u64);
    type State = DomainState;

    fn authorize(
        &self,
        descriptor: &TransitionDescriptor<String, String, RequestContext, String>,
    ) -> Result<(), RejectReason> {
        if self.operation.allowed_actors.contains(&descriptor.actor) {
            Ok(())
        } else {
            Err(RejectReason::DisallowedActor)
        }
    }

    fn validate(
        &self,
        _: &TransitionDescriptor<String, String, RequestContext, String>,
    ) -> Result<(), RejectReason> {
        if self.request.payload.amount == 0 {
            Err(RejectReason::InvariantViolation(
                "amount must be positive".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn mutate_candidate(
        &mut self,
        descriptor: &TransitionDescriptor<String, String, RequestContext, String>,
    ) -> Result<Self::Candidate, AbortReason> {
        Ok((descriptor.asset.clone(), self.request.payload.amount))
    }

    fn reconcile(&mut self, candidate: Self::Candidate) -> Result<(), AbortReason> {
        if self.request.payload.inject_internal_error {
            return Err(AbortReason::InternalFailure(
                "injected failure after candidate creation and before commit".into(),
            ));
        }
        self.state.committed_assets.insert(candidate.0, candidate.1);
        Ok(())
    }

    fn state(&self) -> &Self::State {
        self.state
    }
}

pub fn resolved_policy_canonical(policy: &EffectivePolicy) -> anyhow::Result<Vec<u8>> {
    Ok(canonicalize(policy)?)
}

pub fn quarantine_policy_from(
    policy: &RiskEvidencePolicy,
) -> Result<QuarantinePolicy, RiskModelError> {
    QuarantinePolicy::new(
        policy.enabled,
        policy.minimum_occurrences,
        BasisPoints::new(policy.minimum_severity_bps)?,
        BasisPoints::new(policy.minimum_confidence_bps)?,
        match policy.aggregation {
            RiskEvidenceAggregation::AllThresholds => EvidenceAggregation::AllThresholds,
            RiskEvidenceAggregation::AnyThreshold => EvidenceAggregation::AnyThreshold,
        },
    )
}
