#![cfg(feature = "development-gate")]
//! Held-in-lobby through the real HTTP door: a held member or admin is refused
//! every action the registry does not mark as a lobby step, and root can still
//! repair a community whose admins are all held.
mod support;
use cvld::api::{ACTIONS, Access, Action, Scope};
use cvld::error::Error;
use serde_json::{Value, json};
use support::*;

const HOST: &str = "api.seals.example.test";
const ADMIN_HOST: &str = "api.admin.seals.example.test";
const NOW_SECONDS: u64 = NOW;

/// The smallest body the schema accepts: required fields only, first variant.
fn sample(schema: &Value, root: &Value) -> Value {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().unwrap();
        return sample(&root["$defs"][name], root);
    }
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(first) = schema.get("enum").and_then(|e| e.get(0)) {
        return first.clone();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(options) = schema.get(key).and_then(Value::as_array) {
            let pick = options
                .iter()
                .find(|o| o.get("type") != Some(&json!("null")))
                .unwrap_or(&options[0]);
            return sample(pick, root);
        }
    }
    let kind = match schema.get("type") {
        Some(Value::Array(kinds)) => kinds.iter().find(|k| *k != "null").cloned(),
        other => other.cloned(),
    };
    match kind.as_ref().and_then(Value::as_str) {
        Some("object") | None => {
            let required: Vec<&str> = schema
                .get("required")
                .and_then(Value::as_array)
                .map(|r| r.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut object = serde_json::Map::new();
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, property) in properties {
                    if required.contains(&name.as_str()) {
                        object.insert(name.clone(), sample(property, root));
                    }
                }
            }
            Value::Object(object)
        }
        Some("array") => json!([]),
        Some("string") => json!(""),
        Some("integer") | Some("number") => json!(0),
        Some("boolean") => json!(false),
        _ => Value::Null,
    }
}

fn body_of(action: &Action) -> Value {
    let schema = (action.request)();
    sample(&schema, &schema)
}

async fn post(
    service: &Running,
    host: &str,
    token: &str,
    action: &Action,
) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("{}/v1/{}", service.base, action.name))
        .header("host", host)
        .bearer_auth(token)
        .json(&body_of(action))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

fn is_held(outcome: &(u16, String)) -> bool {
    outcome.0 == 403 && outcome.1.contains("held_in_lobby")
}

/// Run the registry against the door with one held session. Unmarked actions
/// of `access` must be refused as held; marked ones must never be.
async fn table(service: &Running, host: &str, token: &str, access: Access) -> (usize, usize) {
    let mut refused = 0;
    let mut allowed = 0;
    let mut actions: Vec<&Action> = ACTIONS
        .iter()
        .filter(|a| a.access == access && a.scope != Scope::Global)
        .collect();
    // Irreversible lobby steps last.
    actions.sort_by_key(|a| a.name.contains("self_ban"));
    for action in actions {
        let outcome = post(service, host, token, action).await;
        if action.lobby {
            assert!(!is_held(&outcome), "{} is marked and must not be held: {outcome:?}", action.name);
            allowed += 1;
        } else {
            assert!(is_held(&outcome), "{} is unmarked and must be held: {outcome:?}", action.name);
            refused += 1;
        }
    }
    (refused, allowed)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_member_is_refused_every_unmarked_action_and_may_use_every_marked_one() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let community = community("seals", &public).await;
    // Enrolled but never admitted: the community gate is unmet.
    let member = enrol_community(&community, HOST, &passport).await;
    let (refused, allowed) = table(&community, HOST, &member.session, Access::Member).await;
    assert!(refused >= 5 && allowed >= 5, "{refused} refused, {allowed} allowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_admin_cannot_edit_settings_but_completes_the_lobby_and_root_can_repair() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let community = community("seals", &public).await;
    let mut admin = admitted_community_member(&community, "seals", &passport, "seals_admin").await;
    let subject = passport
        .pseudonym(&cpsd::CommunityId::new("seals").unwrap())
        .to_hex();
    preexisting_role(&community, "seals", &subject, crgs::Role::Admin).await;
    let member_session = admin.session.clone();
    let garden = login(
        &community,
        ADMIN_HOST,
        &mut admin.authenticator,
        &admin.user,
        &admin.credential,
    )
    .await;
    let portal = client(&community, ADMIN_HOST, Some(&garden));
    let setting = json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW_SECONDS});
    // In good standing the admin edits settings.
    portal.call("setting_set", setting.clone()).await.unwrap();

    // The gate is withdrawn: the admin is held like anybody else.
    let member_api = client(&community, HOST, Some(&member_session));
    let proof = presentation(&community, HOST, Some(&member_session), &passport).await;
    member_api
        .call(
            "gate_withdraw",
            json!({"gate":"cvch","provider":"sponsor",
                   "credential":{"presentation":proof,"devices":vec![admin.signing_key]}}),
        )
        .await
        .unwrap();
    assert!(matches!(
        portal.call("setting_set", setting.clone()).await,
        Err(Error::HeldInLobby)
    ));
    assert!(matches!(
        portal.call("setting_list", json!({})).await,
        Err(Error::HeldInLobby)
    ));
    let (refused, allowed) = table(&community, ADMIN_HOST, &garden, Access::Admin).await;
    assert!(refused >= 4 && allowed == 0, "{refused} refused, {allowed} allowed");

    // Root is not held and repairs the community while every admin is held.
    let root = enrol(&community, ROOT, Some("synthetic-root-enrolment-capability")).await;
    client(&community, ROOT, Some(&root.session))
        .call(
            "platform_set",
            json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW_SECONDS},"force":true}),
        )
        .await
        .unwrap();

    // The admin completes the lobby steps with the member session and is free again.
    let lobby = member_api.call("lobby", json!({})).await.unwrap();
    assert_eq!(lobby["state"], "lapsed");
    member_api
        .voucher_redeem(voucher("seals", &subject, "replacement-voucher", NOW + 172_800))
        .await
        .unwrap();
    assert!(
        issue_community(&community, HOST, &admin, &passport)
            .await
            .credential
            .is_some()
    );
    portal.call("setting_list", json!({})).await.unwrap();
}
