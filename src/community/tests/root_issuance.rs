//! Linked HTTP source/root owners use real passport, role and passkey authority.
use super::*;
use crate::test_support::*;
use serde_json::json;
use std::sync::atomic::AtomicU64;

#[path = "root_issuance/fixture.rs"]
pub(super) mod fixture;
#[path = "root_issuance/release.rs"]
mod release;
use fixture::*;

const SOURCE: &str = "api.alpha.example.test";
const GARDEN: &str = "api.admin.alpha.example.test";
const ROOT_MEMBER: &str = "api.adminboard.example.test";

/// The admin board is an ordinary community: any ordinary name works (every other test here uses
/// `adminboard`), and a platform host label such as `root` is refused for it like for everyone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_admin_board_takes_no_platform_host_label_as_its_name() {
    let global = global(100).await;
    let (_holder, public) = passport(&global).await;
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("linked-root").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    for label in crate::hub::PLATFORM_HOST_LABELS {
        let opened = root_as(&public, &issuer, label).await;
        assert!(
            matches!(opened.err(), Some(crate::error::Error::Invalid)),
            "{label}"
        );
    }
    assert!(root_as(&public, &issuer, "boardroom").await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_garden_issues_real_joint_credential_and_burns_exact_context() {
    let mut world = world().await;
    let garden = client(&world.source, GARDEN, Some(&world.garden));
    let challenge: RootBoardIssueChallenge = serde_json::from_value(
        garden
            .call("root_board_issue_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let source = anchor(&world.source, SOURCE, "alpha").await;
    let root = anchor(&world.root, ROOT_MEMBER, "adminboard").await;
    let request = world
        .holder
        .begin_root_board_issuance(
            &mut cpsd::rand::rngs::OsRng,
            &root,
            &challenge.signed_context,
            &source,
            &challenge.signed_source_request,
            NOW,
        )
        .unwrap();
    let body = json!({"challenge":challenge.challenge,"proof":request.to_bytes()});
    let answer: Bytes = serde_json::from_value(
        garden
            .call("root_board_issue_finish", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    world
        .holder
        .finish_root_board_issuance(
            &cpsd::BlindRootBoardCredential::from_bytes(&answer.bytes).unwrap(),
        )
        .unwrap();
    assert!(garden.call("root_board_issue_finish", body).await.is_err());

    // Root ADMISSION sees only the original joint proof, never source role or
    // the issuance request. Its genuine public-only owner verifies that proof.
    let challenge: PresentationChallenge = serde_json::from_value(
        client(&world.root, ROOT_MEMBER, None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let proof = world
        .holder
        .present_root_board(&mut cpsd::rand::rngs::OsRng, &root, &challenge.request, NOW)
        .unwrap();
    let response = client(&world.root, ROOT_MEMBER, None)
        .call(
            "register_begin",
            json!({"passport":{"challenge":challenge.challenge,"proof":proof.to_bytes()}}),
        )
        .await
        .unwrap();
    let _: Ceremony = serde_json::from_value(response).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuer_refuses_member_host_member_session_and_current_demotion() {
    let world = world().await;
    for (host, bearer) in [
        (SOURCE, world.garden.as_str()),
        (GARDEN, world.member.session.as_str()),
        (SOURCE, world.member.session.as_str()),
    ] {
        assert!(
            client(&world.source, host, Some(bearer))
                .call("root_board_issue_begin", json!({}))
                .await
                .is_err()
        );
    }
    let garden = client(&world.source, GARDEN, Some(&world.garden));
    let _: RootBoardIssueChallenge = serde_json::from_value(
        garden
            .call("root_board_issue_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    garden
        .call(
            "member_role_set",
            json!({"member":world.holder.pseudonym(&cpsd::CommunityId::new("alpha").unwrap()).to_hex(),"role":"member"}),
        )
        .await
        .unwrap();
    assert!(
        garden
            .call("root_board_issue_begin", json!({}))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_role_owner_uses_live_time_inside_an_older_http_operation_scope() {
    let world = world().await;
    let community = world.source.door.community_backend().unwrap().lock().await;
    let auth = community
        .sessions
        .get(&world.garden)
        .unwrap()
        .authentication
        .clone();
    world.source.clock.set(NOW + 1);
    let lease = crate::service::at(
        NOW,
        crate::service::with_live_clock(community.facade.membership().role_until(&auth, NOW + 60)),
    )
    .await
    .unwrap();
    assert_eq!(lease.checked_at(), NOW + 1);
    assert!(lease.is_current(NOW + 1));
    assert_eq!(lease.valid_until(), NOW + 60);
}
