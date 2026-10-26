//! Boundary tests use the real local stores, signatures and WebAuthn verifier.
use super::*;
use crate::test_support as support;
use serde_json::json;
use std::sync::atomic::AtomicU64;
use support::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

const HOST: &str = "api.alpha.example.test";

async fn public(service: &Running) -> GlobalPublic {
    serde_json::from_value(
        client(service, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn login_response(member: &mut Member, ceremony: Ceremony) -> LoginFinish {
    let options: ckyh::RequestChallengeResponse = serde_json::from_value(ceremony.options).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    LoginFinish {
        ceremony: ceremony.ceremony,
        credential: credential.into(),
    }
}

fn registration_response(
    token: &mut SoftToken,
    options: serde_json::Value,
) -> ckyh::RegisterPublicKeyCredential {
    let options: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    let mut options = options.public_key;
    // SoftToken is a legacy non-resident fixture; UV remains required.
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    token
        .perform_register(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options,
            300_000,
        )
        .unwrap()
        .into()
}

#[tokio::test]
async fn absent_legal_authority_and_unrepresentable_time_fail_closed() {
    use clbs::{Clock as _, Verifier as _};
    let mut signed = clbs::SignedOrder {
        order: clbs::Order {
            community: "alpha".into(),
            id: "order-fixture".into(),
            subject: "opaque-member".into(),
            reference: "opaque-reference".into(),
            entered_by: "opaque-member".into(),
            kind: clbs::OrderKind::SelfBan,
            scope: clbs::Scope::Member,
        },
        proof: b"untrusted-private-authorization".to_vec(),
    };
    let authority =
        CommunityAuthority::new("alpha", Arc::new(TestClock(AtomicU64::new(NOW))), 2).unwrap();
    signed.order.validate().unwrap();
    assert!(matches!(
        authority.verify_self_ban(&signed).await,
        Err(clbs::Error::Denied)
    ));
    signed.order.kind = clbs::OrderKind::Legal {
        authority: "unconfigured-authority".into(),
    };
    signed.order.validate().unwrap();
    assert!(matches!(
        authority.verify_legal(&signed).await,
        Err(clbs::Error::Denied)
    ));
    let clock = Arc::new(TestClock(AtomicU64::new(i64::MAX as u64)));
    assert_eq!(CommunityClock(clock.clone()).now().unwrap(), i64::MAX);
    clock.set(i64::MAX as u64 + 1);
    assert!(matches!(
        CommunityClock(clock).now(),
        Err(clbs::Error::Denied)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configuration_limits_precede_storage_and_valid_state_reopens() {
    let global = global(100).await;
    let public = public(&global).await;
    let dir = tempfile::tempdir().unwrap();
    let base = community_config(dir.path(), "alpha", &public, 100);
    let db = crlt::Db::open(crlt::Config::new(&base.database_url, ""))
        .await
        .unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let base = serde_json::to_value(base).unwrap();
    for (field, value) in [
        ("community", json!("")),
        ("community", json!("a".repeat(64))),
        ("community", json!("Upper")),
        ("community", json!("under_score")),
        ("community", json!("é")),
        // Platform host labels, "root" included, are reserved community names (hub.rs
        // PLATFORM_HOST_LABELS); the loop below covers every one of them.
        ("community", json!("root")),
        ("community", json!("admin")),
        ("community", json!("api")),
        ("community", json!("www")),
        ("community", json!("mail")),
        ("community", json!("mcp")),
        ("community", json!("wallet")),
        ("pending_capacity", json!(0)),
        ("session_seconds", json!(0)),
        ("session_seconds", json!(3601)),
        ("lease_months", json!(0)),
    ] {
        let mut config = base.clone();
        config[field] = value;
        assert!(matches!(
            CommunityService::open(&db, serde_json::from_value(config).unwrap(), clock.clone())
                .await,
            Err(Error::Invalid)
        ));
    }
    for label in crate::hub::PLATFORM_HOST_LABELS {
        let mut config = base.clone();
        config["community"] = json!(label);
        assert!(
            matches!(
                CommunityService::open(&db, serde_json::from_value(config).unwrap(), clock.clone())
                    .await,
                Err(Error::Invalid)
            ),
            "{label}"
        );
    }
    let original = CommunityService::open(
        &db,
        serde_json::from_value(base.clone()).unwrap(),
        clock.clone(),
    )
    .await
    .unwrap();
    let ring = original.public.key_ring.clone();
    drop(original);
    drop(db);
    let db = crlt::Db::open(crlt::Config::new(
        base["database_url"].as_str().unwrap(),
        "",
    ))
    .await
    .unwrap();
    let later = NOW + 60;
    assert_ne!(later, cplc::day(later));
    clock.set(later);
    let mut reopened = CommunityService::open(
        &db,
        serde_json::from_value(base.clone()).unwrap(),
        clock.clone(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.public.key_ring, ring);
    let request = reopened.challenge(None, later).await.unwrap();
    csgn::KeyRing::from_cbor(&ring)
        .unwrap()
        .verify(&request.request, csgn::Kind::Credential, later)
        .unwrap();
    drop(reopened);
    clock.set(cplc::day(NOW) + 86_400);
    let next_day = CommunityService::open(
        &db,
        serde_json::from_value(base.clone()).unwrap(),
        clock.clone(),
    )
    .await
    .unwrap();
    assert_eq!(next_day.public.key_ring, ring);
    drop(next_day);
    // Coarse timestamps are intentional; crossing back over a signing day is not.
    clock.set(later);
    assert!(matches!(
        CommunityService::open(&db, serde_json::from_value(base).unwrap(), clock.clone()).await,
        Err(Error::Unavailable)
    ));

    // Include each accepted character class and the maximum label length.
    clock.set(NOW);
    let dir = tempfile::tempdir().unwrap();
    let name = format!("a1-{}", "a".repeat(60));
    let mut config = community_config(dir.path(), &name, &public, 100);
    config.session_seconds = 3600;
    config.pending_capacity = 1;
    let db = crlt::Db::open(crlt::Config::new(&config.database_url, ""))
        .await
        .unwrap();
    assert_eq!(
        CommunityService::open(&db, config, clock)
            .await
            .unwrap()
            .config
            .community,
        name
    );
}

async fn install_status(config: &CommunityConfig, status: &cgbl::Status, seed: u8) {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cgbl:global",
        csgn::SecretKey::from_seed(&mut [seed; 32]),
        cplc::day(NOW),
        100 * 86_400,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(status).unwrap(),
            NOW,
            NOW + 2 * 86_400,
        )
        .await
        .unwrap();
    std::fs::write(&config.global_status_file, signed).unwrap();
    std::fs::write(
        &config.global_key_ring_file,
        signer.key_ring().unwrap().to_cbor(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_community_keys_and_issuer_changes_remain_separate_from_global_trust() {
    let global = global(100).await;
    let public = public(&global).await;
    let service = community("alpha", &public).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    let ring = csgn::KeyRing::from_cbor(&public.key_ring).unwrap();
    let mut status = cgbl::Status::verify(&public.status, &ring, "global", 1, 1, NOW).unwrap();
    let original_issuer = status.issuer_public_key.clone();
    let replacement = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("replacement-issuer").unwrap(),
        vec![cpsd::GateId::new("development").unwrap()],
    )
    .unwrap();
    // A fully authenticated replacement issuer still requires recomposition.
    status.issuer_public_key = replacement.public_key().to_bytes();
    install_status(&community.config, &status, 4).await;
    assert!(matches!(
        community.challenge(None, NOW).await,
        Err(Error::Refused)
    ));
    assert!(community.challenges.is_empty());
    status.issuer_public_key = original_issuer;
    install_status(&community.config, &status, b'a').await;
    // A different provisioned seed must not hide overlap in the saved key ring.
    std::fs::write(&community.config.signing_seed_file, [7; 32]).unwrap();
    let config = serde_json::from_value(serde_json::to_value(&community.config).unwrap()).unwrap();
    assert!(matches!(
        CommunityService::open(&community.db, config, service.clock.clone()).await,
        Err(Error::Invalid)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_challenges_are_bounded_owned_and_consumed_on_rejection() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    let (_, unregistered_passport, _) = wallet_passport(&global).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    community.config.pending_capacity = 1;
    let first = community.challenge(None, NOW).await.unwrap();
    assert!(matches!(
        community.challenge(None, NOW + 59).await,
        Err(Error::Throttled)
    ));
    let second = community.challenge(None, NOW + 60).await.unwrap();
    assert!(!community.challenges.contains_key(&first.challenge));
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: Some("private-bootstrap".into()),
                    passport: None
                },
                NOW + 60
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: None
                },
                NOW + 60
            )
            .await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: Some(PresentationInput {
                        challenge: second.challenge.clone(),
                        proof: vec![0]
                    })
                },
                NOW + 60
            )
            .await,
        Err(Error::Invalid)
    ));
    assert!(!community.challenges.contains_key(&second.challenge));
    assert!(community.registrations.is_empty());
    let owned = community
        .challenge(Some(ckyh::Uuid::parse_str(&member.user).unwrap()), NOW + 60)
        .await
        .unwrap();
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: Some(PresentationInput {
                        challenge: owned.challenge.clone(),
                        proof: vec![]
                    })
                },
                NOW + 60
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(!community.challenges.contains_key(&owned.challenge));
    let (grant, auth) = community
        .authenticate(&member.session, NOW + 60)
        .await
        .unwrap();
    let ctx = crate::service::Context {
        host: HOST.into(),
        grant: Some(grant),
        token: Some(member.session.clone()),
        now: NOW + 60,
        authentication: Some(auth),
    };
    let anonymous = community.challenge(None, NOW + 60).await.unwrap();
    assert!(matches!(
        community
            .issue(
                &ctx,
                CredentialRequest {
                    presentation: PresentationInput {
                        challenge: anonymous.challenge.clone(),
                        proof: vec![]
                    },
                    devices: vec![member.signing_key],
                    creation: None,
                },
                None,
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(!community.challenges.contains_key(&anonymous.challenge));
    drop(community);

    // A real, accepted passport can reserve only the configured ceremony count.
    let proof = presentation(&service, HOST, None, &unregistered_passport).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    let pending = community
        .register_begin(
            RegisterStart {
                bootstrap: None,
                passport: Some(proof),
            },
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: None
                },
                NOW + 299
            )
            .await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        community
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: None
                },
                NOW + 300
            )
            .await,
        Err(Error::Invalid)
    ));
    assert!(!community.registrations.contains_key(&pending.ceremony));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_capacity_expiry_and_session_credential_binding_fail_closed() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, HOST, &passport).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    community.config.pending_capacity = 1;
    // The community's creator holds a session of its own from setup; this test is
    // about the capacity of exactly one, so only the member's session stays.
    community
        .sessions
        .retain(|token, _| *token == member.session);
    let request = || LoginStart {
        user: member.user.clone(),
        credential: member.credential.clone(),
    };
    let first = community.login_begin(request(), NOW).await.unwrap();
    assert!(matches!(
        community.login_begin(request(), NOW).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        community.login_discoverable_begin(NOW).await,
        Err(Error::Throttled)
    ));
    let finish = login_response(&mut member, first);
    let encoded = serde_json::to_value(&finish).unwrap();
    assert!(matches!(
        community.login_finish(finish, NOW).await,
        Err(Error::Throttled)
    ));
    assert_eq!(community.logins.len(), 1);
    community.logout("unknown-session");
    assert_eq!(community.sessions.len(), 1);
    community.logout(&member.session);
    let session = community
        .login_finish(serde_json::from_value(encoded).unwrap(), NOW)
        .await
        .unwrap();
    assert!(community.logins.is_empty());
    let original = community
        .sessions
        .get(&session.token)
        .unwrap()
        .grant
        .credential
        .clone();
    community
        .sessions
        .get_mut(&session.token)
        .unwrap()
        .grant
        .credential = vec![254; 32].into();
    assert!(matches!(
        community.authenticate(&session.token, NOW).await,
        Err(Error::Unauthorized)
    ));
    community
        .sessions
        .get_mut(&session.token)
        .unwrap()
        .grant
        .credential = original;
    assert!(community.authenticate(&session.token, NOW).await.is_ok());

    let expired = community
        .login_begin(
            LoginStart {
                user: member.user.clone(),
                credential: member.credential.clone(),
            },
            NOW,
        )
        .await
        .unwrap();
    let finish = login_response(&mut member, expired);
    community.logout(&session.token);
    assert!(matches!(
        community.login_finish(finish, NOW + 300).await,
        Err(Error::Unauthorized)
    ));
    assert!(community.logins.is_empty());
    let discoverable = community.login_discoverable_begin(NOW + 300).await.unwrap();
    community.prune(NOW + 600);
    assert!(!community.logins.contains_key(&discoverable.ceremony));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn additional_passkey_checks_all_session_bindings_and_releases_expired_capacity() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, HOST, &passport).await;
    let alternate = login(
        &service,
        HOST,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    let (grant, auth) = community.authenticate(&member.session, NOW).await.unwrap();
    let (other_grant, other_auth) = community.authenticate(&alternate, NOW).await.unwrap();
    let mut unknown = grant.clone();
    unknown.session_id = [0; 32];
    assert!(matches!(
        community
            .add_passkey(&auth, &unknown, AddPasskey::Begin, NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    community
        .sessions
        .get_mut(&member.session)
        .unwrap()
        .grant
        .user = ckyh::Uuid::new_v4();
    assert!(matches!(
        community
            .add_passkey(&auth, &grant, AddPasskey::Begin, NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    community
        .sessions
        .get_mut(&member.session)
        .unwrap()
        .grant
        .user = grant.user;
    community
        .sessions
        .get_mut(&member.session)
        .unwrap()
        .grant
        .credential = vec![254; 32].into();
    assert!(matches!(
        community
            .add_passkey(&auth, &grant, AddPasskey::Begin, NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    community
        .sessions
        .get_mut(&member.session)
        .unwrap()
        .grant
        .credential = grant.credential.clone();
    assert!(community.additions.is_empty());

    community.config.pending_capacity = 1;
    let AddedPasskey::Challenge { ceremony, .. } = community
        .add_passkey(&auth, &grant, AddPasskey::Begin, NOW)
        .await
        .unwrap()
    else {
        panic!("challenge")
    };
    assert!(matches!(
        community
            .add_passkey(&other_auth, &other_grant, AddPasskey::Begin, NOW + 299)
            .await,
        Err(Error::Throttled)
    ));
    let AddedPasskey::Challenge {
        ceremony: replacement,
        options,
        ..
    } = community
        .add_passkey(&other_auth, &other_grant, AddPasskey::Begin, NOW + 300)
        .await
        .unwrap()
    else {
        panic!("challenge")
    };
    assert!(!community.additions.contains_key(&ceremony));
    let credential = registration_response(&mut SoftToken::new(true).unwrap().0, options);
    community
        .add_passkey(
            &other_auth,
            &other_grant,
            AddPasskey::Finish {
                ceremony: replacement,
                credential: Box::new(credential),
            },
            NOW + 300,
        )
        .await
        .unwrap();
    // Revocation through the domain owner must invalidate a cached session too.
    community
        .facade
        .membership()
        .revoke_passkey(&auth, grant.credential)
        .await
        .unwrap();
    assert!(matches!(
        community.authenticate(&member.session, NOW + 300).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_refreshes_only_stale_or_incoherent_publication() {
    let global = global(100).await;
    let public = public(&global).await;
    let service = community("alpha", &public).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    let mut changes = community.changes.subscribe();
    let epoch = community.public.policy_epoch;
    community.maintain(NOW).await.unwrap();
    assert!(!changes.has_changed().unwrap());
    community.public.policy_epoch += 1;
    community.maintain(NOW).await.unwrap();
    assert!(changes.has_changed().unwrap());
    assert_eq!(community.public.policy_epoch, epoch);
    changes.borrow_and_update();
    community.public.manifest = b"corrupt-cached-manifest".to_vec();
    community.maintain(NOW).await.unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    let ring = csgn::KeyRing::from_cbor(&community.public.key_ring).unwrap();
    let until = ring
        .verify(
            &community.public.manifest,
            csgn::Kind::SettingsSnapshot,
            NOW,
        )
        .unwrap()
        .valid_until();
    let boundary = until - community.config.publication_seconds / 2;
    community.maintain(boundary).await.unwrap();
    assert!(changes.has_changed().unwrap());
    ring.verify(
        &community.public.manifest,
        csgn::Kind::SettingsSnapshot,
        boundary,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_authorization_drains_pending_revocation_and_unknown_fields_refuse_pins() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, HOST, &passport).await;
    let c = client(&service, HOST, Some(&member.session));
    let lobby: Lobby = serde_json::from_value(c.call("lobby", json!({})).await.unwrap()).unwrap();
    let pin = cmbr::PinV2::seal(
        &cpns::FingerprintContext {
            community: "alpha",
            member: &lobby.member_id,
            field: "unknown",
        },
        b"true",
        &cpns::Salt::from_bytes(vec![21; 32]).unwrap(),
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "pin_set",
            json!({"field":"unknown", "pin":pin})
        )
        .await,
        400
    );
    assert!(c.call("pin_get", json!({"field":"unknown"})).await.unwrap()["pin"].is_null());
    c.call("handle_reserve", json!({"handle":"member_one"}))
        .await
        .unwrap();
    c.voucher_redeem(voucher(
        "alpha",
        &lobby.member_id,
        "replace-device",
        NOW + 86_400,
    ))
    .await
    .unwrap();
    assert!(
        issue_community(&service, HOST, &member, &passport)
            .await
            .credential
            .is_some()
    );
    let before: TrustFeed =
        serde_json::from_value(c.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let proof = support::step_up(
        &service,
        HOST,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"passkey_add"}),
    )
    .await;
    let addition: AddedPasskey = serde_json::from_value(
        c.call("passkey_add", json!({"step":"begin","step_up":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = addition
    else {
        panic!("challenge")
    };
    let credential = registration_response(&mut SoftToken::new(true).unwrap().0, options);
    let added_id = credential.raw_id.as_ref().to_vec();
    c.call(
        "passkey_add",
        json!({"step":"finish", "ceremony":ceremony, "credential":credential}),
    )
    .await
    .unwrap();
    {
        let mut community = service.door.community_backend().unwrap().lock().await;
        let (_, auth) = community.authenticate(&member.session, NOW).await.unwrap();
        // Model a committed domain revocation awaiting host outbox maintenance.
        community
            .facade
            .membership()
            .revoke_passkey(&auth, added_id.into())
            .await
            .unwrap();
    }
    let key = member.signing_key;
    let proof = support::step_up(
        &service,
        HOST,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"device_authorize","key":key}),
    )
    .await;
    let keys: DeviceKeys = serde_json::from_value(
        c.call("device_authorize", json!({"key":key,"step_up":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(keys.keys.contains(&key));
    let after: TrustFeed =
        serde_json::from_value(c.call("trust_feed", json!({})).await.unwrap()).unwrap();
    assert!(after.revision > before.revision);
    assert!(after.policy_epoch > before.policy_epoch);
    let ring = csgn::KeyRing::from_cbor(&after.key_ring).unwrap();
    let snapshot: cplc::Snapshot<cplc::Revocations> = cplc::verify_snapshot(
        &ring,
        &after.revocations,
        cplc::SnapshotExpectation {
            community: "alpha",
            kind: cplc::SnapshotKind::RevocationList,
            minimum_revision: 1,
            policy_epoch: after.policy_epoch,
            now: NOW,
        },
    )
    .unwrap();
    assert_eq!(snapshot.policy_epoch, after.policy_epoch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verified_legal_veto_after_authentication_prevents_credential_issuance() {
    use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

    // An explicit fixture authority authenticates the complete order. The
    // service's unconfigured submission authority remains fail-closed.
    struct Authority(VerifyingKey);
    impl clbs::Verifier for Authority {
        async fn verify_legal(&self, signed: &clbs::SignedOrder) -> clbs::Result<()> {
            if signed.order.entered_by != "fixture-root"
                || signed.order.kind
                    != (clbs::OrderKind::Legal {
                        authority: "fixture-authority".into(),
                    })
            {
                return Err(clbs::Error::Denied);
            }
            let signature =
                Signature::from_slice(&signed.proof).map_err(|_| clbs::Error::Denied)?;
            self.0
                .verify_strict(&signed.order.signing_payload()?, &signature)
                .map_err(|_| clbs::Error::Denied)
        }

        async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
            Err(clbs::Error::Denied)
        }
    }

    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    let c = client(&service, HOST, Some(&member.session));
    let lobby: Lobby = serde_json::from_value(c.call("lobby", json!({})).await.unwrap()).unwrap();
    c.call("handle_reserve", json!({"handle":"member_one"}))
        .await
        .unwrap();
    c.voucher_redeem(voucher(
        "alpha",
        &lobby.member_id,
        "pre-veto-voucher",
        NOW + 86_400,
    ))
    .await
    .unwrap();
    assert!(
        issue_community(&service, HOST, &member, &passport)
            .await
            .credential
            .is_some()
    );
    let presentation = presentation(&service, HOST, Some(&member.session), &passport).await;
    let challenge_id = presentation.challenge.clone();
    let mut community = service.door.community_backend().unwrap().lock().await;
    let (grant, auth) = community.authenticate(&member.session, NOW).await.unwrap();
    let ctx = crate::service::Context {
        host: HOST.into(),
        grant: Some(grant),
        token: Some(member.session.clone()),
        now: NOW,
        authentication: Some(auth),
    };
    let order = clbs::Order {
        community: "alpha".into(),
        id: "private-order-reference".into(),
        subject: lobby.member_id.clone(),
        reference: "private-authority-reference".into(),
        entered_by: "fixture-root".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-authority".into(),
        },
        scope: clbs::Scope::Member,
    };
    let key = SigningKey::from_bytes(&[41; 32]);
    let proof = key
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    let authority = clbs::Gate::new(
        cgts::legal_storage::LibsqlStore::new(&community.db, "alpha").unwrap(),
        Authority(key.verifying_key()),
    );
    let mut signed = clbs::SignedOrder { order, proof };
    signed.order.reference.push_str("-tampered");
    assert!(matches!(
        authority.record_legal(&signed).await,
        Err(clbs::Error::Denied)
    ));
    signed
        .order
        .reference
        .truncate("private-authority-reference".len());
    assert_eq!(
        authority.record_legal(&signed).await.unwrap(),
        clbs::Append::Inserted
    );
    assert!(matches!(
        authority.check(&lobby.member_id).await.unwrap(),
        clbs::State::Red(_)
    ));

    // The member and passport were authenticated before the legal order landed.
    // The actual admission path must still recheck the owning legal gate.
    let result = community
        .issue(
            &ctx,
            CredentialRequest {
                presentation,
                devices: vec![member.signing_key],
                creation: None,
            },
            None,
        )
        .await;
    assert!(matches!(result, Err(Error::Forbidden)));
    assert!(!community.challenges.contains_key(&challenge_id));
    let error = result.err().unwrap();
    assert_eq!(
        serde_json::to_value(crate::error::ErrorBody::from(error)).unwrap(),
        json!({"error":"forbidden"})
    );
}

/// Fixture legal authority for community-scope orders. Production stays
/// fail-closed (`CommunityAuthority::verify_legal` denies); tests authenticate
/// a complete order through this fixture instead. Verification is unchanged:
/// the same authority and verifier path as member orders, only the scope
/// differs.
struct CommunityFixtureAuthority(ed25519_dalek::VerifyingKey);

impl clbs::Verifier for CommunityFixtureAuthority {
    async fn verify_legal(&self, signed: &clbs::SignedOrder) -> clbs::Result<()> {
        if signed.order.entered_by != "fixture-root"
            || signed.order.kind
                != (clbs::OrderKind::Legal {
                    authority: "fixture-authority".into(),
                })
        {
            return Err(clbs::Error::Denied);
        }
        let signature =
            ed25519_dalek::Signature::from_slice(&signed.proof).map_err(|_| clbs::Error::Denied)?;
        self.0
            .verify_strict(&signed.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }

    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}

/// Record a community-scope legal order for "alpha" through the owning legal
/// gate and prove the stored records report Red.
async fn record_community_order(community: &CommunityService, id: &str) {
    use ed25519_dalek::{Signer as _, SigningKey};
    let order = clbs::Order {
        community: "alpha".into(),
        id: id.into(),
        subject: "alpha".into(),
        reference: "private-authority-reference".into(),
        entered_by: "fixture-root".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-authority".into(),
        },
        scope: clbs::Scope::Community,
    };
    let key = SigningKey::from_bytes(&[41; 32]);
    let proof = key
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    let store = cgts::legal_storage::LibsqlStore::new(&community.db, "alpha").unwrap();
    let authority = clbs::Gate::new(
        store.clone(),
        CommunityFixtureAuthority(key.verifying_key()),
    );
    assert_eq!(
        authority
            .record_legal(&clbs::SignedOrder { order, proof })
            .await
            .unwrap(),
        clbs::Append::Inserted
    );
    let records = clbs::Store::orders(&store, "alpha").await.unwrap();
    assert!(matches!(
        clbs::community_legal_state("alpha", &records),
        clbs::State::Red(_)
    ));
}

/// Pass the lobby and voucher gates so the test reaches the admission decision.
async fn prepare_admission(service: &Running, member: &Member, handle: &str, voucher_id: &str) {
    let c = client(service, HOST, Some(&member.session));
    c.call("handle_reserve", json!({"handle": handle}))
        .await
        .unwrap();
    let lobby: Lobby = serde_json::from_value(c.call("lobby", json!({})).await.unwrap()).unwrap();
    c.voucher_redeem(voucher("alpha", &lobby.member_id, voucher_id, NOW + 86_400))
        .await
        .unwrap();
}

async fn credential_issue_call(
    service: &Running,
    member: &Member,
    proof: PresentationInput,
) -> u16 {
    call_status(
        service,
        HOST,
        Some(&member.session),
        "credential_issue",
        json!({"presentation": proof, "devices": [member.signing_key]}),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_red_community_refuses_admission() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    prepare_admission(&service, &member, "red_admit", "red-admit-voucher").await;
    // Fetch the presentation while the community is still green: building it
    // reads the discovery feed, which is also gone once the community is red.
    let proof = presentation(&service, HOST, Some(&member.session), &passport).await;
    {
        let community = service.door.community_backend().unwrap().lock().await;
        record_community_order(&community, "community-block").await;
    }
    // Lobby and voucher gates still run under a red community; only the
    // admission decision itself is refused.
    assert_eq!(credential_issue_call(&service, &member, proof).await, 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_red_community_refuses_credential_renewal() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    prepare_admission(&service, &member, "red_renew", "red-renew-voucher").await;
    assert!(
        issue_community(&service, HOST, &member, &passport)
            .await
            .credential
            .is_some()
    );
    // Fetch the renewal presentation while green; renewing under Red is refused.
    let proof = presentation(&service, HOST, Some(&member.session), &passport).await;
    {
        let community = service.door.community_backend().unwrap().lock().await;
        record_community_order(&community, "community-block").await;
    }
    // The member was admitted while green; renewing under Red is refused.
    assert_eq!(credential_issue_call(&service, &member, proof).await, 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_red_community_is_excluded_from_the_trust_feed() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    client(&service, HOST, Some(&member.session))
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    {
        let community = service.door.community_backend().unwrap().lock().await;
        record_community_order(&community, "community-block").await;
    }
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "trust_feed",
            json!({})
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_green_community_admits_renews_and_lists_unchanged() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    prepare_admission(&service, &member, "green_member", "green-voucher").await;
    // A member-scope order for someone else never reddens the community.
    {
        let community = service.door.community_backend().unwrap().lock().await;
        let store = cgts::legal_storage::LibsqlStore::new(&community.db, "alpha").unwrap();
        let records = clbs::Store::orders(&store, "alice").await.unwrap();
        assert_eq!(
            clbs::community_legal_state("alpha", &records),
            clbs::State::Green
        );
    }
    assert!(
        issue_community(&service, HOST, &member, &passport)
            .await
            .credential
            .is_some()
    );
    assert!(
        issue_community(&service, HOST, &member, &passport)
            .await
            .credential
            .is_some()
    );
    client(&service, HOST, Some(&member.session))
        .call("trust_feed", json!({}))
        .await
        .unwrap();
}

/// A newly created community's charter settings project into Forum's settings without
/// configuration: the mechanics are code constants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_community_has_valid_forum_settings() {
    let global = global(100).await;
    let public = public(&global).await;
    let dir = tempfile::tempdir().unwrap();
    let base = community_config(dir.path(), "alpha", &public, 100);
    let db = crlt::Db::open(crlt::Config::new(&base.database_url, ""))
        .await
        .unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let service = CommunityService::open(&db, base, clock).await.unwrap();
    let snapshot = service
        .facade
        .policy()
        .lock()
        .await
        .settings(NOW)
        .await
        .unwrap();
    let forum = crbk::ForumSettings::from_snapshot(&snapshot).unwrap();
    assert_eq!(
        forum.room_passes_per_epoch,
        crbk::FORUM_ROOM_PASSES_PER_EPOCH
    );
    assert_eq!(forum.lease_ms, crbk::FORUM_LEASE_MS);
}
