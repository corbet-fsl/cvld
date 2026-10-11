//! Real admitted key, separately stepped-up garden sessions and original roles.
use super::root_issuance_tests::fixture::world;
use super::*;
use crate::test_support::*;
use serde_json::json;
use webauthn_authenticator_rs::AuthenticatorBackend as _;

#[path = "garden/commit.rs"]
mod commit;

const SOURCE: &str = "api.alpha.example.test";
const GARDEN: &str = "api.admin.alpha.example.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_and_garden_sessions_are_distinct_and_signup_does_not_create_admins() {
    let world = world().await;
    let member = client(&world.source, SOURCE, Some(&world.member.session));
    let role: MemberRole =
        serde_json::from_value(member.call("member_role", json!({})).await.unwrap()).unwrap();
    assert_eq!(role.role, Role::Root);
    let owner = world.source.door.community_backend().unwrap().lock().await;
    assert_eq!(
        owner
            .sessions
            .get(&world.member.session)
            .unwrap()
            .grant
            .role,
        Role::Member
    );
    assert!(!owner.sessions.get(&world.member.session).unwrap().garden);
    assert!(owner.sessions.get(&world.garden).unwrap().garden);
    drop(owner);
    for (host, bearer) in [(GARDEN, &world.member.session), (SOURCE, &world.garden)] {
        let (status, _) =
            call_status(&world.source, host, Some(bearer), "member_role", json!({})).await;
        assert_eq!(status, 401);
    }
    let (status, _) = call_status(
        &world.source,
        GARDEN,
        None,
        "register_begin",
        json!({"passport":null,"bootstrap":"configured-operator-is-not-a-member"}),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call_status(
        &world.source,
        SOURCE,
        Some(&world.member.session),
        "member_role_set",
        json!({"member":role.member,"role":"admin"}),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_finish_cannot_move_a_real_member_challenge_to_the_garden() {
    let mut world = world().await;
    let member = client(&world.source, SOURCE, None);
    let start: Ceremony = serde_json::from_value(
        member
            .call(
                "login_begin",
                json!({"user":world.member.user,"credential":world.member.credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let options: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let response = world
        .member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{SOURCE}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    let body = json!({"ceremony":start.ceremony,"credential":response});
    let (status, _) = call_status(&world.source, GARDEN, None, "login_finish", body.clone()).await;
    assert_eq!(status, 401);
    // The original server pending is consumed by the wrong-realm attempt;
    // neither a role flag nor a new challenge is fabricated on retry.
    let (status, _) = call_status(&world.source, SOURCE, None, "login_finish", body).await;
    assert_eq!(status, 401);
    assert!(
        client(&world.source, SOURCE, Some(&world.member.session))
            .call("member_role", json!({}))
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garden_logout_removes_only_the_exact_garden_session() {
    let world = world().await;
    let garden = client(&world.source, GARDEN, Some(&world.garden));
    garden.call("logout", json!({})).await.unwrap();
    let (status, _) = call_status(
        &world.source,
        GARDEN,
        Some(&world.garden),
        "root_board_issue_begin",
        json!({}),
    )
    .await;
    assert_eq!(status, 401);
    assert!(
        client(&world.source, SOURCE, Some(&world.member.session))
            .call("member_role", json!({}))
            .await
            .is_ok()
    );
}
