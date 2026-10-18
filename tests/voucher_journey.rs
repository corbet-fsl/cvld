#![cfg(feature = "development-gate")]
//! Journey rows 15 and 16 on the host: an admitted member registers a real voucher
//! link (only its hashes), a newcomer redeems it and is admitted with a credential.
//! A single-use one-hour link needs no sign-off; a multi-use link waits for the
//! issuer's decision. The first sponsor is bootstrapped with the development link
//! (nobody earlier could vouch for it); every later step is the product path.
mod support;
use cvld::service::Clock as _;
use serde_json::{Value, json};
use support::*;

const SCOPE: &str = "journey";
const HOST: &str = "api.journey.example.test";

fn subject(passport: &cpsd::Passport) -> String {
    passport
        .pseudonym(&cpsd::CommunityId::new(SCOPE).unwrap())
        .to_hex()
}

/// A link as the issuer's device makes it: the token and the registration body.
fn link(sponsor: [u8; 32], uses: u32, valid_for: u64) -> (cvch::link::Token, Value) {
    let (token, _secret) = cvch::link::Token::generate(sponsor).unwrap();
    let registration = token.registration();
    let body = json!({
        "id": registration.id().as_str(),
        "verifier": registration.verifier(),
        "manage_verifier": registration.manage_verifier(),
        "uses": uses,
        "valid_for": valid_for,
        "signoff": null,
    });
    (token, body)
}

fn manage(token: &cvch::link::Token) -> Value {
    json!({
        "id": token.registration().id().as_str(),
        "secret": token.manage().secret_hex().to_string(),
    })
}

/// The newcomer's redemption: the sealed notice names its pseudonym and handle.
fn redeem(token: &cvch::link::Token, member: &str, handle: &str) -> Value {
    let notice = cvch::link::Notice {
        member: member.into(),
        nonce: [9; 16],
        handle: Some(handle.into()),
        key_package: Vec::new(),
    };
    let request = cvch::link::Request::new(token, &notice).unwrap();
    json!({"id": request.id, "secret": request.secret, "notice": request.notice})
}

/// A newcomer enrolled with its own passport and holding a reserved handle.
async fn newcomer(
    global: &Running,
    community: &Running,
    handle: &str,
) -> (Member, cpsd::Passport, String) {
    let (_, passport, _) = wallet_passport(global).await;
    let member = enrol_community(community, HOST, &passport).await;
    client(community, HOST, Some(&member.session))
        .call("handle_reserve", json!({"handle": handle}))
        .await
        .unwrap();
    let id = subject(&passport);
    (member, passport, id)
}

async fn lobby(community: &Running, member: &Member) -> Value {
    client(community, HOST, Some(&member.session))
        .call("lobby", json!({}))
        .await
        .unwrap()
}

async fn lobby_state(community: &Running, member: &Member) -> String {
    lobby(community, member).await["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_members_one_use_one_hour_link_admits_one_newcomer_without_sign_off() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let community = community(SCOPE, &public).await;
    let (_, sponsor_passport, _) = wallet_passport(&global).await;
    let sponsor =
        admitted_community_member(&community, SCOPE, &sponsor_passport, "journey_sponsor").await;
    let sponsor_api = client(&community, HOST, Some(&sponsor.session));

    // Row 15: one use, one hour; an ordinary member's single-use link needs no sign-off.
    let now = community.clock.now();
    let (token, body) = link([4; 32], 1, 3600);
    let created = sponsor_api.call("voucher_link_create", body).await.unwrap();
    assert_eq!(created["signoff"], json!(false));
    assert_eq!(created["expires_at"], json!(now + 3600));
    let view = sponsor_api
        .call("voucher_link_view", manage(&token))
        .await
        .unwrap();
    assert_eq!(view["uses"], json!(1));
    assert!(view["waiting"].as_array().unwrap().is_empty());

    // The sponsor's own lobby names its role: its device sizes the allowance by it.
    assert_eq!(lobby(&community, &sponsor).await["role"], json!("member"));

    // Row 16: the newcomer redeems and is admitted; the credential follows.
    let (bob, bob_passport, bob_id) = newcomer(&global, &community, "journey_bob").await;
    let bob_api = client(&community, HOST, Some(&bob.session));
    // Not admitted yet: no role.
    assert!(lobby(&community, &bob).await.get("role").is_none());
    bob_api
        .call("voucher_redeem", redeem(&token, &bob_id, "journey_bob"))
        .await
        .unwrap();
    let issued = issue_community(&community, HOST, &bob, &bob_passport).await;
    assert_eq!(issued.lobby.state, "admitted");
    assert!(issued.credential.is_some());
    assert_eq!(lobby(&community, &bob).await["role"], json!("member"));
    // The issuer's device sees the admission (and the sealed notice to derive the bond).
    let view = sponsor_api
        .call("voucher_link_view", manage(&token))
        .await
        .unwrap();
    let admitted = view["admitted"].as_array().unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0]["member"], json!(bob_id));

    // The one use is spent: a second newcomer with the same link is not admitted.
    let (carol, _, carol_id) = newcomer(&global, &community, "journey_carol").await;
    let carol_api = client(&community, HOST, Some(&carol.session));
    assert!(
        carol_api
            .call("voucher_redeem", redeem(&token, &carol_id, "journey_carol"))
            .await
            .is_err()
    );
    assert_ne!(lobby_state(&community, &carol).await, "admitted");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admins_lobby_names_the_admin_role() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let community = community(SCOPE, &public).await;
    let (_, passport, _) = wallet_passport(&global).await;
    let mut admin = admitted_community_member(&community, SCOPE, &passport, "journey_admin").await;
    preexisting_role(&community, SCOPE, &subject(&passport), crgs::Role::Admin).await;
    admin.session = login(
        &community,
        HOST,
        &mut admin.authenticator,
        &admin.user,
        &admin.credential,
    )
    .await;
    assert_eq!(lobby(&community, &admin).await["role"], json!("admin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_hour_link_admits_nobody_after_the_hour() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let community = community(SCOPE, &public).await;
    let (_, sponsor_passport, _) = wallet_passport(&global).await;
    let sponsor =
        admitted_community_member(&community, SCOPE, &sponsor_passport, "journey_sponsor").await;
    let (token, body) = link([4; 32], 1, 3600);
    client(&community, HOST, Some(&sponsor.session))
        .call("voucher_link_create", body)
        .await
        .unwrap();
    let (late, _, late_id) = newcomer(&global, &community, "journey_late").await;
    community.clock.set(community.clock.now() + 3601);
    let refused = client(&community, HOST, Some(&late.session))
        .call("voucher_redeem", redeem(&token, &late_id, "journey_late"))
        .await;
    assert!(refused.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_multi_use_link_admits_only_after_the_issuers_confirmation() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let community = community(SCOPE, &public).await;
    let (_, sponsor_passport, _) = wallet_passport(&global).await;
    let sponsor =
        admitted_community_member(&community, SCOPE, &sponsor_passport, "journey_sponsor").await;
    let sponsor_api = client(&community, HOST, Some(&sponsor.session));
    let (token, body) = link([4; 32], 2, 3600);
    let created = sponsor_api.call("voucher_link_create", body).await.unwrap();
    assert_eq!(created["signoff"], json!(true));

    // Row 16 with sign-off: the redemption is accepted but waits in the lobby.
    let (bob, bob_passport, bob_id) = newcomer(&global, &community, "journey_bob").await;
    let bob_api = client(&community, HOST, Some(&bob.session));
    let presented = redeem(&token, &bob_id, "journey_bob");
    bob_api
        .call("voucher_redeem", presented.clone())
        .await
        .unwrap();
    assert_ne!(lobby_state(&community, &bob).await, "admitted");

    // The issuer lists the applicant (without a session: the management secret is the
    // authority, so the host never learns which member manages the link) and confirms.
    let waiting = client(&community, HOST, None)
        .call("voucher_signoff_list", manage(&token))
        .await
        .unwrap();
    let waiting = waiting["waiting"].as_array().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0]["member"], json!(bob_id));
    let mut decide = manage(&token);
    decide["member"] = json!(bob_id);
    decide["confirm"] = json!(true);
    let decision = client(&community, HOST, None)
        .call("voucher_signoff_decide", decide)
        .await
        .unwrap();
    assert_eq!(decision["admitted"], json!(true));

    // Presenting the same link again learns the decision; the credential follows.
    bob_api.call("voucher_redeem", presented).await.unwrap();
    let issued = issue_community(&community, HOST, &bob, &bob_passport).await;
    assert_eq!(issued.lobby.state, "admitted");
    assert!(issued.credential.is_some());

    // A declined applicant stays out.
    let (dave, _, dave_id) = newcomer(&global, &community, "journey_dave").await;
    client(&community, HOST, Some(&dave.session))
        .call("voucher_redeem", redeem(&token, &dave_id, "journey_dave"))
        .await
        .unwrap();
    let mut decline = manage(&token);
    decline["member"] = json!(dave_id);
    decline["confirm"] = json!(false);
    let decision = client(&community, HOST, None)
        .call("voucher_signoff_decide", decline)
        .await
        .unwrap();
    assert_eq!(decision["admitted"], json!(false));
    assert_ne!(lobby_state(&community, &dave).await, "admitted");
}
