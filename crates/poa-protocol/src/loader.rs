use std::{fs, path::Path};

use serde_json::Value;

use crate::{PolicyError, ProtocolSpec, validate_value};

pub fn load_schema(path: impl AsRef<Path>) -> Result<Value, PolicyError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn load_and_validate(
    path: impl AsRef<Path>,
    schema: &Value,
) -> Result<ProtocolSpec, PolicyError> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    validate_value(&value, schema)
}
