//! Real GlobalRoot and passport-derived target; no role fixture or deployment.
use super::*;
use crate::test_support::*;
use serde_json::json;

const TARGET: &str = "api.alpha.example.test";
const BOOTSTRAP: &str = "synthetic-operator-enrolment-capability";

struct World {
    global: Running,
    target: Running,
    operator: Member,
    member: Member,
    passport: cpsd::Passport,
}
impl World {
    async fn new() -> Self {
        let global = global(200).await;
        let (_, passport, public) = wallet_passport(&global).await;
        let operator = enrol(&global, ROOT, Some(BOOTSTRAP)).await;
        let target = community_unfounded("alpha", &public).await;
        let member = enrol_community(&target, TARGET, &passport).await;
        global
            .door
            .link_community_creation(&target.door)
            .await
            .unwrap();
        Self {
            global,
            target,
            operator,
            member,
            passport,
        }
    }
    async fn prepare(&self, id: Option<&str>) -> CreationRecipient {
        serde_json::from_value(
            client(&self.target, TARGET, Some(&self.member.session))
                .call(
                    "community_creation_recipient",
                    json!({"id":id,"expires_at":NOW+300}),
                )
                .await
                .unwrap(),
        )
        .unwrap()
    }
    async fn initialize(&self, recipient: &CreationRecipient) -> Result<serde_json::Value> {
        client(&self.global, ROOT, Some(&self.operator.session))
            .call(
                "community_creation_initialize",
                json!({"community":"alpha","recipient":recipient.recipient}),
            )
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_root_two_database_creation_requires_original_full_gates_for_root_admission() {
    let world = World::new().await;
    let prepared = world.prepare(None).await;
    let created: CommunityCreationInvitation =
        serde_json::from_value(world.initialize(&prepared).await.unwrap()).unwrap();
    assert_eq!(created.id, prepared.id);
    assert_eq!(created.expires_at, prepared.expires_at);
    let target = world.target.door.community_backend().unwrap().lock().await;
    assert_eq!(
        target.facade.membership().community_phase().await.unwrap(),
        cmty::cmbr::CommunityPhase::Creating
    );
    drop(target);
    assert!(matches!(
        world.initialize(&prepared).await,
        Err(Error::Refused)
    ));
    let retry = world.prepare(Some(&prepared.id)).await;
    let equal: CommunityCreationInvitation =
        serde_json::from_value(world.initialize(&retry).await.unwrap()).unwrap();
    assert_eq!(equal.id, created.id);
    assert_eq!(equal.expires_at, created.expires_at);
    let scope = cpsd::CommunityId::new("alpha").unwrap();
    let subject = world.passport.pseudonym(&scope).to_hex();
    let api = client(&world.target, TARGET, Some(&world.member.session));
    api.call("handle_reserve", json!({"handle":"creator_one"}))
        .await
        .unwrap();
    let before = presentation(
        &world.target,
        TARGET,
        Some(&world.member.session),
        &world.passport,
    )
    .await;
    let denied = api.call("credential_issue", json!({"presentation":before,"devices":[world.member.signing_key],"creation":created.invitation})).await;
    // Without the configured gate nothing is issued and the member stays outside.
    let denied: CredentialResponse = serde_json::from_value(denied.unwrap()).unwrap();
    assert!(denied.credential.is_none());
    api.call(
        "gate_voucher",
        voucher("alpha", &subject, "ordinary-full-gate", NOW + 172800),
    )
    .await
    .unwrap();
    let proof = presentation(
        &world.target,
        TARGET,
        Some(&world.member.session),
        &world.passport,
    )
    .await;
    let issued: CredentialResponse = serde_json::from_value(api.call("credential_issue", json!({"presentation":proof,"devices":[world.member.signing_key],"creation":equal.invitation})).await.unwrap()).unwrap();
    assert!(issued.credential.is_some());
    assert_eq!(issued.lobby.state, "admitted");
    let role: MemberRole =
        serde_json::from_value(api.call("member_role", json!({})).await.unwrap()).unwrap();
    assert_eq!(serde_json::to_value(role).unwrap()["role"], "root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recipient_reference_never_selects_a_foreign_session_and_logout_refuses_before_creation() {
    let world = World::new().await;
    let prepared = world.prepare(None).await;
    assert_eq!(
        call_status(
            &world.global,
            ROOT,
            Some(&world.member.session),
            "community_creation_initialize",
            json!({"community":"alpha","recipient":prepared.recipient})
        )
        .await,
        401
    );
    client(&world.target, TARGET, Some(&world.member.session))
        .call("logout", json!({}))
        .await
        .unwrap();
    assert!(matches!(
        world.initialize(&prepared).await,
        Err(Error::Refused | Error::Reconcile)
    ));
    let target = world.target.door.community_backend().unwrap().lock().await;
    assert_eq!(
        target.facade.membership().community_phase().await.unwrap(),
        cmty::cmbr::CommunityPhase::Uninitialized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_original_root_scope_fences_the_actual_independent_sdk_writer() {
    let world = World::new().await;
    let keys = world
        .global
        .door
        .auth(ROOT)
        .unwrap()
        .lock()
        .await
        .passkeys
        .clone();
    let user = ckyh::Uuid::parse_str(&world.operator.user).unwrap();
    let credential: ckyh::CredentialID = world.operator.credential.clone().into();
    let observed_keys = keys.clone();
    let original = tokio::task::spawn_blocking(move || observed_keys.list(user))
        .await
        .unwrap()
        .unwrap();
    assert!(
        original
            .iter()
            .any(|key| key.credential_id() == &credential && !key.is_revoked())
    );
    let writer = world
        .global
        .door
        .inner
        .root_creation_scope
        .as_ref()
        .unwrap()
        .tx()
        .await
        .unwrap();
    let attempted_keys = keys.clone();
    let attempted_credential = credential.clone();
    let attempted =
        tokio::task::spawn_blocking(move || attempted_keys.revoke(user, &attempted_credential))
            .await
            .unwrap();
    assert_eq!(attempted, Err(ckyh::Error::Storage));
    let observed_keys = keys.clone();
    let retained = tokio::task::spawn_blocking(move || observed_keys.list(user))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(retained).unwrap(),
        serde_json::to_value(original).unwrap()
    );
    writer.rollback().await.unwrap();
    tokio::task::spawn_blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        call_status(
            &world.global,
            ROOT,
            Some(&world.operator.session),
            "passkey_list",
            json!({})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_same_file_factory_isolation_preserves_the_existing_root_owner() {
    let world = World::new().await;
    let mut config = CommunityConfig::read(
        world
            .target
            .dir
            .path()
            .join("config.json")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    config.database_url = format!(
        "file://{}",
        world.global.dir.path().join("global.db").display()
    );
    assert!(
        Door::community(config, world.target.clock.clone())
            .await
            .is_err()
    );
    assert_eq!(
        call_status(
            &world.global,
            ROOT,
            Some(&world.operator.session),
            "passkey_list",
            json!({})
        )
        .await,
        200
    );
    assert_eq!(
        call_status(&world.global, WALLET, None, "global_public", json!({})).await,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_creation_session_is_bound_to_its_grant_expiry_inside_the_publication_scope() {
    use crate::{api::Effect, service::publication::Publication};
    let world = World::new().await;
    let token = world.operator.session.clone();
    let clock = world.global.clock.clone();
    let auth = world.global.door.auth(ROOT).unwrap();
    let mut auth = auth.lock().await;
    let grant = auth.authenticate(&token, NOW).await.unwrap();
    let context = Context {
        host: ROOT.into(),
        grant: Some(grant.clone()),
        token: Some(token.clone()),
        now: NOW,
        authentication: None,
    };
    let mut session = auth
        .root_creation_session(&token, &grant, NOW, clock.as_ref())
        .await
        .unwrap();
    // Sampling inside the grant never narrows the action to the sampling instant.
    let inside = Publication::new(clock.clone(), &context, Effect::Record)
        .run(async {
            session
                .check(&mut auth, &token, clock.as_ref())
                .await
                .map(|_| ())
        })
        .await;
    assert!(inside.is_ok());
    // A grant that ends before the final publication check withholds the result.
    let outside = Publication::new(clock.clone(), &context, Effect::Record)
        .run(async {
            session.check(&mut auth, &token, clock.as_ref()).await?;
            clock.set(grant.expires);
            Ok(())
        })
        .await;
    assert!(matches!(outside, Err(Error::Reconcile)));
}
