use poa_protocol::{canonicalize_value, strict_json};
use serde_json::json;
#[test]
fn ordered_arrays_remain_ordered_and_unicode_is_not_normalized() {
    assert_ne!(
        canonicalize_value(&json!({"sequence":[1,2]})).unwrap(),
        canonicalize_value(&json!({"sequence":[2,1]})).unwrap()
    );
    assert_eq!(
        canonicalize_value(&json!({"pledge_promises":["stdio","rpath"]})).unwrap(),
        canonicalize_value(&json!({"pledge_promises":["rpath","stdio"]})).unwrap()
    );
    assert_ne!(
        canonicalize_value(&json!({"x":"é"})).unwrap(),
        canonicalize_value(&json!({"x":"e\u{301}"})).unwrap()
    );
    assert!(strict_json::parse(br#"{"x":"\uD800"}"#).is_err());
}
