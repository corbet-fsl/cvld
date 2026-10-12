//! Genuine role and key authority at actual native policy storage commits.
use super::*;
use crate::community::garden::GardenCommit;
use cplc::Storage as _;

fn context(owner: &CommunityService, token: &str) -> crate::service::Context {
    let session = owner.sessions.get(token).unwrap();
    crate::service::Context {
        host: GARDEN.into(),
        grant: Some(session.grant.clone()),
        token: Some(token.into()),
        now: NOW,
        authentication: Some(session.authentication.clone()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_schema_commit_succeeds_then_independent_key_revocation_refuses_next_cas() {
    let world = world().await;
    let owner = world.source.door.community_backend().unwrap().lock().await;
    let ctx = context(&owner, &world.garden);
    let auth = ctx.authentication.as_ref().unwrap();
    let mut lease = owner
        .garden_lease(auth, NOW, ctx.grant.as_ref().unwrap().expires)
        .await
        .unwrap();
    let mut policy = owner.facade.policy().lock().await;
    {
        let mut guard = GardenCommit::new(&owner, &ctx, &mut lease, "schema_set");
        policy
            .set_schema_checked(community_schema("alpha", 2), &mut guard)
            .await
            .unwrap();
    }
    let store = cplc::LibsqlStore::new(&owner.db, "alpha").unwrap();
    let before = store.load().await.unwrap();
    assert_eq!(
        serde_json::to_value(&before).unwrap()["schema"]["version"],
        2
    );
    // A second SDK owner mutates the original credential row, independently of
    // Membership's process member lease. No role/key result is synthesized.
    let keys = ckyh::Passkeys::new(
        ckyh::LibsqlStore::new(&owner.db, "alpha", tokio::runtime::Handle::current()).unwrap(),
        "alpha",
        "alpha.example.test",
        &[ckyh::Url::parse("https://api.alpha.example.test").unwrap()],
    )
    .unwrap();
    let user = auth.member();
    let credential = auth.credential_id().clone();
    tokio::task::spawn_blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    {
        let mut guard = GardenCommit::new(&owner, &ctx, &mut lease, "schema_set");
        assert!(
            policy
                .set_schema_checked(community_schema("alpha", 3), &mut guard)
                .await
                .is_err()
        );
    }
    assert_eq!(store.load().await.unwrap(), before);
    assert!(!lease.is_current(NOW));
    assert!(matches!(policy.schema(), Err(cplc::Error::ReloadRequired)));
}
