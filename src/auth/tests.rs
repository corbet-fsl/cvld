//! Exercise refusals through real passkey ceremonies and a local SQL store.
use super::*;
use crate::test_support::resident;
use resident::{Resident, strip_prf};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://auth.example.test";
const BOOTSTRAP: &str = "synthetic-operator-enrolment-capability";

#[path = "tests/enrollment.rs"]
mod enrollment;
#[path = "tests/global_self_ban.rs"]
mod global_self_ban;
#[path = "tests/passkey_management.rs"]
mod passkey_management;

async fn database() -> (tempfile::TempDir, crlt::Db) {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("auth.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
        .await
        .unwrap();
    (directory, db)
}

fn keys(db: &crlt::Db) -> Passkeys<LibsqlStore> {
    Passkeys::new(
        LibsqlStore::new(db, "auth", tokio::runtime::Handle::current()).unwrap(),
        "auth",
        "auth.example.test",
        &[ckyh::Url::parse(ORIGIN).unwrap()],
    )
    .unwrap()
}

fn auth(db: &crlt::Db, operator: Option<Uuid>, capacity: usize) -> Auth {
    Auth::new(
        keys(db),
        if operator.is_some() {
            Role::Root
        } else {
            Role::Member
        },
        operator,
        operator.map(|_| zeroize::Zeroizing::new(BOOTSTRAP.into())),
        capacity,
        600,
    )
    .unwrap()
}

fn start(bootstrap: Option<&str>) -> RegisterStart {
    RegisterStart {
        bootstrap: bootstrap.map(str::to_owned),
        passport: None,
    }
}

async fn registration(device: &mut Resident, begin: Ceremony) -> RegisterFinish {
    let mut response = device.ceremony(begin.options, true, ORIGIN).await;
    strip_prf(&mut response);
    RegisterFinish {
        ceremony: begin.ceremony,
        credential: serde_json::from_value(response).unwrap(),
    }
}

async fn login(auth: &mut Auth, device: &mut Resident) -> LoginFinish {
    let begin = auth.login_discoverable_begin(NOW).await.unwrap();
    let mut response = device.ceremony(begin.options, false, ORIGIN).await;
    strip_prf(&mut response);
    LoginFinish {
        ceremony: begin.ceremony,
        credential: serde_json::from_value(response).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_auth_configuration_refuses_zero_and_oversized_limits() {
    let (_directory, db) = database().await;
    for (capacity, lifetime, bootstrap) in [
        (0, 600, None),
        (1, 0, None),
        (1, 3601, None),
        (1, 600, Some("x".repeat(31))),
        (1, 600, Some("x".repeat(1025))),
    ] {
        assert!(matches!(
            Auth::new(
                keys(&db),
                Role::Root,
                Some(Uuid::new_v4()),
                bootstrap.map(zeroize::Zeroizing::new),
                capacity,
                lifetime
            ),
            Err(Error::Invalid)
        ));
    }
    for length in [32, 1024] {
        assert!(
            Auth::new(
                keys(&db),
                Role::Root,
                Some(Uuid::new_v4()),
                Some(zeroize::Zeroizing::new("x".repeat(length))),
                1,
                3600
            )
            .is_ok()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_capacity_expires_without_authorizing_forbidden_bootstrap_inputs() {
    let (_directory, db) = database().await;
    let mut member = auth(&db, None, 1);
    assert!(matches!(
        member.register_begin(start(Some(BOOTSTRAP)), NOW).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        member
            .register_begin(
                RegisterStart {
                    bootstrap: None,
                    passport: Some(PresentationInput {
                        challenge: "foreign".into(),
                        proof: vec![1]
                    }),
                },
                NOW
            )
            .await,
        Err(Error::Invalid)
    ));
    member.register_begin(start(None), NOW).await.unwrap();
    assert!(matches!(
        member.register_begin(start(None), NOW).await,
        Err(Error::Throttled)
    ));
    member.register_begin(start(None), NOW + 300).await.unwrap();
    member.login_discoverable_begin(NOW).await.unwrap();
    assert!(matches!(
        member.login_discoverable_begin(NOW).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        member
            .login_begin(
                LoginStart {
                    user: Uuid::new_v4().to_string(),
                    credential: vec![]
                },
                NOW
            )
            .await,
        Err(Error::Throttled)
    ));
    member.login_discoverable_begin(NOW + 300).await.unwrap();

    let mut root = auth(&db, Some(Uuid::new_v4()), 1);
    for supplied in [
        None,
        Some("wrong"),
        Some("synthetic-operator-enrolment-capabilitX"),
    ] {
        assert!(matches!(
            root.register_begin(start(supplied), NOW).await,
            Err(Error::Forbidden)
        ));
    }
    assert!(matches!(
        root.login_begin(
            LoginStart {
                user: "private-invalid-uuid".into(),
                credential: vec![]
            },
            NOW
        )
        .await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        root.login_begin(
            LoginStart {
                user: Uuid::new_v4().to_string(),
                credential: vec![]
            },
            NOW
        )
        .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_bootstrap_ceremonies_cannot_register_a_second_operator_key() {
    let (_directory, db) = database().await;
    let operator = Uuid::new_v4();
    let mut root = auth(&db, Some(operator), 2);
    let first = root
        .register_begin(start(Some(BOOTSTRAP)), NOW)
        .await
        .unwrap();
    let second = root
        .register_begin(start(Some(BOOTSTRAP)), NOW)
        .await
        .unwrap();
    let first = registration(&mut Resident::default(), first).await;
    let second = registration(&mut Resident::default(), second).await;
    assert_eq!(
        root.register_finish(first, NOW).await.unwrap().user,
        operator.to_string()
    );
    assert!(root.bootstrap.is_none());
    assert!(matches!(
        root.register_finish(second, NOW).await,
        Err(Error::Refused)
    ));
    assert!(matches!(
        root.register_begin(start(Some(BOOTSTRAP)), NOW).await,
        Err(Error::Forbidden)
    ));
    let mut reopened = auth(&db, Some(operator), 2);
    assert!(matches!(
        reopened.register_begin(start(Some(BOOTSTRAP)), NOW).await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_refuses_a_valid_foreign_operator_and_malformed_assertion() {
    let (_directory, db) = database().await;
    let mut member = auth(&db, None, 2);
    let mut device = Resident::default();
    let begin = member.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    member.register_finish(finish, NOW).await.unwrap();
    let mut root = auth(&db, Some(Uuid::new_v4()), 2);
    let finish = login(&mut root, &mut device).await;
    assert!(matches!(
        root.login_finish(finish, NOW).await,
        Err(Error::Unauthorized)
    ));
    assert!(root.sessions.is_empty());

    let finish = login(&mut member, &mut device).await;
    let mut bytes = serde_json::to_value(&finish).unwrap();
    bytes["credential"]["response"]["signature"] = serde_json::json!("AA");
    assert!(matches!(
        member
            .login_finish(serde_json::from_value(bytes).unwrap(), NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        member.login_finish(finish, NOW).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_capacity_logout_and_revocation_preserve_real_authentication() {
    let (_directory, db) = database().await;
    let mut member = auth(&db, None, 1);
    let mut device = Resident::default();
    let begin = member.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    member.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut member, &mut device).await;
    let first = member.login_finish(finish, NOW).await.unwrap();
    let grant = member.authenticate(&first.token, NOW).await.unwrap();
    assert_eq!(grant.user.to_string(), first.user);
    let finish = login(&mut member, &mut device).await;
    let saved = serde_json::to_value(&finish).unwrap();
    assert!(matches!(
        member.login_finish(finish, NOW).await,
        Err(Error::Throttled)
    ));
    member.logout(&first.token);
    assert!(matches!(
        member.authenticate(&first.token, NOW).await,
        Err(Error::Unauthorized)
    ));
    let second = member
        .login_finish(serde_json::from_value(saved).unwrap(), NOW)
        .await
        .unwrap();
    let passkeys = member.passkeys.clone();
    tokio::task::spawn_blocking(move || passkeys.revoke(grant.user, &grant.credential))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        member.authenticate(&second.token, NOW).await,
        Err(Error::Unauthorized)
    ));
    assert!(!member.sessions.contains_key(&second.token));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_rejects_unsupported_calendar_time_without_storing_a_credential() {
    let (_directory, db) = database().await;
    let mut member = auth(&db, None, 1);
    for now in [253_402_300_800, i64::MAX as u64] {
        let begin = member.register_begin(start(None), now).await.unwrap();
        let finish = registration(&mut Resident::default(), begin).await;
        assert!(matches!(
            member.register_finish(finish, now).await,
            Err(Error::Invalid)
        ));
        assert!(member.registrations.is_empty());
    }
}
