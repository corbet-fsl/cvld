use super::*;
use crate::{config::RootCommunityConfig, service::Door};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct ReleaseClock {
    base: Arc<TestClock>,
    pub samples: AtomicUsize,
    pub advance_at: AtomicUsize,
}
impl Clock for ReleaseClock {
    fn now(&self) -> u64 {
        let sample = self.samples.fetch_add(1, Ordering::SeqCst) + 1;
        if sample == self.advance_at.load(Ordering::SeqCst) {
            self.base.set(NOW + 1);
        }
        self.base.now()
    }
}

pub(crate) struct World {
    pub source: Running,
    pub root: Running,
    pub holder: cpsd::OpaqueHolder,
    pub member: Member,
    pub garden: String,
    pub root_clock: Arc<ReleaseClock>,
    _global: Running,
}

pub(super) async fn anchor(
    service: &Running,
    host: &str,
    scope: &str,
) -> cpsd::AuthenticatedCommunity {
    let feed: TrustFeed = serde_json::from_value(
        client(service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(scope).unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    )
}

pub(super) async fn passport(global: &Running) -> (cpsd::OpaqueHolder, GlobalPublic) {
    let member = enrol(global, WALLET, None).await;
    let client = client(global, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed_and_sealing_key(
        &mut [81; 32],
        &mut [82; 32],
        b"linked-root-issuer-fixture",
    )
    .unwrap();
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let answer: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({
                    "challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),
                }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&answer.bytes).unwrap())
        .unwrap();
    (holder, public)
}

async fn presentation(
    source: &Running,
    holder: &cpsd::OpaqueHolder,
    session: Option<&str>,
) -> PresentationInput {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(source, SOURCE, session)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = anchor(source, SOURCE, "alpha").await;
    let proof = holder
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    PresentationInput {
        challenge: challenge.challenge,
        proof: proof.to_bytes(),
    }
}

async fn root(public: &GlobalPublic, issuer: &cpsd::IssuerKey) -> (Running, Arc<ReleaseClock>) {
    root_as(public, issuer, "adminboard").await.unwrap()
}

/// The admin board under an arbitrary community name; the name alone grants no board role.
pub(super) async fn root_as(
    public: &GlobalPublic,
    issuer: &cpsd::IssuerKey,
    name: &str,
) -> crate::error::Result<(Running, Arc<ReleaseClock>)> {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer.public_key().clone(),
        cpsd::CommunityId::new(name).unwrap(),
        1,
        NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    let path = directory.path().join("root-public");
    std::fs::write(&path, descriptor.to_bytes()).unwrap();
    let config = RootCommunityConfig::new(
        community_config(directory.path(), name, public, 100),
        path.to_str().unwrap().into(),
    )
    .unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let observer = Arc::new(ReleaseClock {
        base: clock.clone(),
        samples: AtomicUsize::new(0),
        advance_at: AtomicUsize::new(0),
    });
    let door = Door::root_board(config, observer.clone()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::api::router(door.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Ok((
        Running {
            base,
            door,
            clock,
            task,
            dir: directory,
        },
        observer,
    ))
}

pub(crate) async fn world() -> World {
    let global = global(100).await;
    let (holder, public) = passport(&global).await;
    let source = community("alpha", &public).await;
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("linked-root").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let (root, root_clock) = root(&public, &issuer).await;
    let purpose = root.door.root_board_purpose(issuer).await.unwrap();
    source
        .door
        .attach_root_board_purpose(purpose.clone())
        .await
        .unwrap();
    assert!(
        source
            .door
            .attach_root_board_purpose(purpose.clone())
            .await
            .is_err()
    );
    assert!(root.door.attach_root_board_purpose(purpose).await.is_err());

    let proof = presentation(&source, &holder, None).await;
    let ceremony: Ceremony = serde_json::from_value(
        client(&source, SOURCE, None)
            .call("register_begin", json!({"passport":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut member = finish_enrol(&source, SOURCE, ceremony).await;
    let member_id = holder
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    let member_client = client(&source, SOURCE, Some(&member.session));
    member_client
        .call("handle_reserve", json!({"handle":"source_root"}))
        .await
        .unwrap();
    member_client
        .voucher_redeem(voucher("alpha", &member_id, "linked-source", NOW + 172_800))
        .await
        .unwrap();
    let proof = presentation(&source, &holder, Some(&member.session)).await;
    let issued: CredentialResponse = serde_json::from_value(
        member_client
            .call(
                "credential_issue",
                json!({"presentation":proof,"devices":[member.signing_key]}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(issued.lobby.state, "admitted");
    {
        let owner = source.door.community_backend().unwrap().lock().await;
        let auth = &owner.sessions.get(&member.session).unwrap().authentication;
        let row = owner.facade.membership().resume(auth).await.unwrap();
        // Trusted fixture initialization through the original register AFTER
        // genuine admission. This is not a first-root bootstrap qualification.
        crgs::Register::new(
            crgs::LibsqlStorage::new(owner.db.community("alpha").unwrap()),
            crgs::ReleasePeriod::default(),
        )
        .set_role(&row.member_id(), crgs::Role::Root)
        .await
        .unwrap();
    }
    let garden = login(
        &source,
        GARDEN,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    World {
        source,
        root,
        holder,
        member,
        garden,
        root_clock,
        _global: global,
    }
}
