//! Genuine role/key/legal authority at actual native policy storage commits.
use super::*;
use crate::community::garden::GardenCommit;
use cplc::{
    Storage as _,
    crbk::{CommitGuard, Storage as _},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

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
    let mut guard = GardenCommit::new(&owner, &ctx, &mut lease, "schema_set");
    policy
        .set_schema_checked(community_schema("alpha", 2), &mut guard)
        .await
        .unwrap();
    drop(guard);
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
    let mut guard = GardenCommit::new(&owner, &ctx, &mut lease, "schema_set");
    assert!(
        policy
            .set_schema_checked(community_schema("alpha", 3), &mut guard)
            .await
            .is_err()
    );
    drop(guard);
    assert_eq!(store.load().await.unwrap(), before);
    assert!(!lease.is_current(NOW));
    assert!(matches!(policy.schema(), Err(cplc::Error::ReloadRequired)));
}

struct Authority(VerifyingKey);
impl clbs::Verifier for Authority {
    async fn verify_legal(&self, signed: &clbs::SignedOrder) -> clbs::Result<()> {
        if signed.order.entered_by != "fixture-root"
            || signed.order.kind
                != (clbs::OrderKind::Legal {
                    authority: "fixture-signature-authority".into(),
                })
        {
            return Err(clbs::Error::Denied);
        }
        let signature = Signature::from_slice(&signed.proof).map_err(|_| clbs::Error::Denied)?;
        self.0
            .verify_strict(&signed.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}

struct Advance<'a> {
    real: GardenCommit<'a>,
    clock: Arc<TestClock>,
}
impl CommitGuard for Advance<'_> {
    async fn check(&mut self) -> cplc::crbk::Result<()> {
        // Deliberately model time advancing after actual SQL staging. The real
        // owner callback still determines authority; no accepting verdict exists.
        self.clock.set(NOW + 1);
        self.real.check().await
    }
    fn release(&mut self) -> cplc::crbk::Result<()> {
        self.real.release()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_operation_restriction_at_final_sql_cut_preserves_original_rulebook() {
    let world = world().await;
    let owner = world.source.door.community_backend().unwrap().lock().await;
    let ctx = context(&owner, &world.garden);
    let mut lease = owner
        .garden_lease(
            ctx.authentication.as_ref().unwrap(),
            NOW,
            ctx.grant.as_ref().unwrap().expires,
        )
        .await
        .unwrap();
    let order = clbs::Order {
        community: "alpha".into(),
        id: "scheduled-garden-setting".into(),
        subject: lease.member().into(),
        reference: "explicit real signature fixture".into(),
        entered_by: "fixture-root".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
        scope: clbs::Scope::Actions(["setting_set".into()].into()),
        period: clbs::Period {
            starts_at: (NOW + 1) as i64,
            ends_at: None,
        },
    };
    let key = SigningKey::from_bytes(&[41; 32]);
    let proof = key
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    let legal = clbs::Gate::new(
        cgts::legal_storage::LibsqlStore::new(&owner.db, "alpha").unwrap(),
        Authority(key.verifying_key()),
        CommunityClock(world.source.clock.clone()),
    );
    assert_eq!(
        legal
            .record_legal(&clbs::SignedOrder { order, proof })
            .await
            .unwrap(),
        clbs::Append::Inserted
    );
    assert!(matches!(
        legal.check_action(lease.member(), "setting_set").await,
        Ok(clbs::State::Green)
    ));
    let rules = cplc::crbk::LibsqlStore::new(owner.db.clone());
    let before = rules
        .load("alpha", cplc::crbk::Selection::Latest)
        .await
        .unwrap();
    let mut policy = owner.facade.policy().lock().await;
    let mut guard = Advance {
        real: GardenCommit::new(&owner, &ctx, &mut lease, "setting_set"),
        clock: world.source.clock.clone(),
    };
    assert!(
        policy
            .edit_setting_checked(
                "quota",
                cplc::SettingEdit::Community(Some(json!(5))),
                NOW,
                NOW + 2,
                0,
                &mut guard
            )
            .await
            .is_err()
    );
    drop(guard);
    assert_eq!(
        rules
            .load("alpha", cplc::crbk::Selection::Latest)
            .await
            .unwrap(),
        before
    );
    assert!(!lease.is_current(NOW + 1));
    assert!(matches!(
        legal.check_action(lease.member(), "setting_set").await,
        Ok(clbs::State::Red(_))
    ));
    assert!(matches!(
        legal.check_action(lease.member(), "schema_set").await,
        Ok(clbs::State::Green)
    ));
}
