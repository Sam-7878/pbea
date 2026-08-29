use sha2::{Digest, Sha256};

use crate::{EffectivePolicy, canonicalize};

pub fn policy_digest(policy: &EffectivePolicy) -> Result<String, serde_json::Error> {
    let bytes = canonicalize(policy)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
