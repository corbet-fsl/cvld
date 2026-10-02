use super::*;
use serde_json::{Value, json};

#[test]
fn duplicate_keys_are_rejected_at_every_depth_before_values_are_collapsed() {
    for bytes in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
        br#"{"outer":{"token":"first","token":"last"}}"#,
        br#"[{"role":"member","role":"root"}]"#,
        br#"{"a":[]"#,
        br#"[true,]"#,
        b"{} {}",
        &[0xff],
    ] {
        assert!(matches!(
            decode::<Value>(bytes),
            Err(crate::error::Error::Reconcile)
        ));
    }
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(decode::<Value>(deep.as_bytes()).is_err());
    let bytes = br#"[null,true,false,-1,18446744073709551615,1.25,"hello",{},[],{"a":1},{"a":2}]"#;
    assert_eq!(
        decode::<Value>(bytes).unwrap(),
        json!([null,true,false,-1,u64::MAX,1.25,"hello",{},[],{"a":1},{"a":2}])
    );
    assert!(decode::<crate::error::ErrorBody>(b"{}").is_err());
}
