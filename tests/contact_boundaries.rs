//! Pure contact scenarios use maintained normalization and fallback planning.
#![cfg(feature = "server")]
use cvld::contact_gates::{self, Error};
use serde_json::{Value, json};

fn offer(channel: &str, maximum: Value, exact: bool, outcome: &str) -> Value {
    json!({"channel":channel,"maximum":maximum,"exact":exact,"source":"explicit hypothetical all-in tariff","valid_until":200,"outcome":outcome})
}
fn amount(atoms: u64) -> Value {
    json!({"unit":"fixture-fee","scale":0,"atoms":atoms})
}
fn request(destination: &str, offers: Vec<Value>) -> Value {
    json!({"destination":destination,"offers":offers,"budget":amount(12),"max_attempts":3,"order":"configured"})
}
fn simulate(value: Value) -> contact_gates::Result<Value> {
    let result = contact_gates::simulation::simulate(
        serde_json::from_value(value).unwrap(),
        b"local-scenario",
        100,
    )?;
    Ok(serde_json::to_value(result).unwrap())
}

#[test]
fn mailbox_safe_failure_can_fallback_but_pending_uncertain_and_refused_stop() {
    for state in ["success", "pending", "uncertain", "refused"] {
        let result = simulate(request(
            "Member+alias@example.test",
            vec![
                offer("email", amount(4), true, state),
                offer("email", amount(3), false, "success"),
            ],
        ))
        .unwrap();
        assert_eq!(result["simulated"], true);
        assert_eq!(result["outcome"], state);
        assert_eq!(result["attempts"], 1);
        assert_eq!(result["exposure"]["atoms"], 4);
        assert!(result.get("operation").is_none());
        assert!(result.get("gate").is_none());
    }
    let result = simulate(request(
        "Member+alias@example.test",
        vec![
            offer("email", amount(4), false, "safe_failure"),
            offer("email", amount(3), false, "success"),
        ],
    ))
    .unwrap();
    assert_eq!(result["outcome"], "success");
    assert_eq!(result["attempts"], 2);
    assert_eq!(result["exposure"]["atoms"], 7);
}

#[test]
fn compatible_phone_channels_use_the_actual_requested_cost_order() {
    let mut value = request(
        "+12025550123",
        vec![
            offer("call", amount(8), true, "refused"),
            offer("whatsapp", amount(3), true, "success"),
        ],
    );
    let configured = simulate(value.clone()).unwrap();
    assert_eq!(configured["outcome"], "refused");
    assert_eq!(configured["exposure"]["atoms"], 8);
    value["order"] = json!("cheapest");
    let cheapest = simulate(value).unwrap();
    assert_eq!(cheapest["outcome"], "success");
    assert_eq!(cheapest["attempts"], 1);
    assert_eq!(cheapest["exposure"]["atoms"], 3);
}

#[test]
fn unknown_expired_or_incompatible_contact_prices_never_authorize_simulated_dispatch() {
    for channel in ["sms", "email"] {
        let destination = if channel == "email" {
            "member@example.test"
        } else {
            "+12025550123"
        };
        assert!(matches!(
            simulate(request(
                destination,
                vec![offer(channel, Value::Null, false, "success")]
            )),
            Err(Error::Budget)
        ));
        let mut expired = offer(channel, amount(4), false, "success");
        expired["valid_until"] = json!(100);
        assert!(matches!(
            simulate(request(destination, vec![expired])),
            Err(Error::Budget)
        ));
        let mut foreign = amount(4);
        foreign["unit"] = json!("other-fee");
        assert!(matches!(
            simulate(request(
                destination,
                vec![offer(channel, foreign, false, "success")]
            )),
            Err(Error::Budget)
        ));
    }
    assert!(matches!(
        simulate(request(
            "+12025550123",
            vec![
                offer("sms", amount(4), false, "safe_failure"),
                offer("email", amount(3), false, "success")
            ]
        )),
        Err(Error::Input)
    ));
    let mut bounded = request(
        "member@example.test",
        vec![
            offer("email", amount(4), false, "safe_failure"),
            offer("email", amount(3), false, "success"),
        ],
    );
    bounded["max_attempts"] = json!(1);
    assert!(matches!(simulate(bounded), Err(Error::Budget)));
}

#[test]
fn contact_simulation_refuses_invalid_identifiers_unbounded_lists_and_amounts() {
    for destination in ["not-a-phone", "", "+12025550123 ext. 42"] {
        assert!(matches!(
            simulate(request(
                destination,
                vec![offer("sms", amount(4), false, "success")]
            )),
            Err(Error::Input)
        ));
    }
    assert!(matches!(
        simulate(request(
            "not-a-mailbox",
            vec![offer("email", amount(4), false, "success")]
        )),
        Err(Error::Input)
    ));
    assert!(matches!(
        simulate(request(
            &"a".repeat(321),
            vec![offer("email", amount(4), false, "success")]
        )),
        Err(Error::Input)
    ));
    assert!(matches!(
        simulate(request("member@example.test", vec![])),
        Err(Error::Input)
    ));
    assert!(matches!(
        simulate(request(
            "member@example.test",
            vec![offer("email", amount(4), false, "success"); 65]
        )),
        Err(Error::Input)
    ));
    let mut invalid = amount(4);
    invalid["scale"] = json!(19);
    assert!(matches!(
        simulate(request(
            "member@example.test",
            vec![offer("email", invalid, false, "success")]
        )),
        Err(Error::Configuration)
    ));
    let mut excessive_source = offer("email", amount(4), false, "success");
    excessive_source["source"] = json!("a".repeat(2049));
    assert!(matches!(
        simulate(request("member@example.test", vec![excessive_source])),
        Err(Error::Input)
    ));
}
