use serde::Serialize;
use serde_json::{Map, Value};

use crate::EffectivePolicy;

fn normalize(value: Value, parent_key: Option<&str>) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| {
                        let normalized = normalize(v, Some(&k));
                        (k, normalized)
                    })
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => {
            let mut values: Vec<_> = values.into_iter().map(|v| normalize(v, None)).collect();
            if matches!(
                parent_key,
                Some(
                    "allowed_actors"
                        | "required_context"
                        | "pledge_promises"
                        | "unveil_paths"
                        | "inbound"
                        | "outbound"
                )
            ) {
                values.sort_by_key(|v| serde_json::to_string(v).unwrap());
                values.dedup();
            } else if parent_key == Some("operations") {
                values.sort_by_key(|v| {
                    v.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                });
            }
            Value::Array(values)
        }
        scalar => scalar,
    }
}

/// Canonicalize an arbitrary serializable policy value.
///
/// This routine performs no semantic validation. Callers must deserialize into
/// a fail-closed type before canonicalization. Object keys are sorted and only
/// explicitly set-like protocol arrays are reordered.
pub fn canonicalize_value<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&normalize(serde_json::to_value(value)?, None))
}

pub fn canonicalize(policy: &EffectivePolicy) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(policy)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("privilege_expansion");
    }
    serde_json::to_vec(&normalize(value, None))
}
