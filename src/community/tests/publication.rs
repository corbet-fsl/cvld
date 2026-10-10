//! The HTTP feed carries the original publisher's continuity proof intact.
use super::*;
use crate::test_support::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_key_rotation_reaches_the_http_feed_and_authenticates_the_new_ring() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let client = client(&service, "api.alpha.example.test", None);
    let initial: TrustFeed =
        serde_json::from_value(client.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let pinned = csgn::KeyRing::from_cbor(&initial.key_ring).unwrap();
    assert!(initial.key_transitions.is_empty());
    let original = {
        let mut community = service.door.community_backend().unwrap().lock().await;
        let mut policy = community.facade.policy().lock().await;
        policy
            .rotate(csgn::SecretKey::from_seed(&mut [241; 32]), NOW)
            .await
            .unwrap();
        let original = policy.key_transitions().unwrap()[0].clone();
        drop(policy);
        community.refresh(NOW).await.unwrap();
        original
    };
    let response = client.call("trust_feed", json!({})).await.unwrap();
    // No configured accounting/root-board publication means absence, not an
    // invented document that a consumer might mistake for signed authority.
    assert!(response.get("balance").is_none());
    assert!(response.get("root_board").is_none());
    let feed: TrustFeed = serde_json::from_value(response).unwrap();
    assert_eq!(feed.key_transitions.len(), 1);
    assert_eq!(feed.key_transitions[0].revision, original.revision);
    assert_eq!(feed.key_transitions[0].proof, original.proof);
    let transition = csgn::verify_transition(&pinned, &feed.key_transitions[0].proof, NOW).unwrap();
    assert_eq!(transition.revision(), feed.key_transitions[0].revision);
    assert_eq!(transition.next().to_cbor(), feed.key_ring);
    transition
        .next()
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    transition
        .next()
        .verify(&feed.settings, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    assert_eq!(feed.policy_epoch, initial.policy_epoch);
    assert!(feed.revision > initial.revision);
}
