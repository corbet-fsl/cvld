//! Real founding of fixture communities through the one production path:
//! a registered recipient, the Global Root's creation entitlement and ordinary
//! full-gate redemption. A community admits nobody until this has happened.
//! There is no hook, flag or alias that activates a community without it.
use super::*;
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

const OPERATOR_CAPABILITY: &str = "synthetic-operator-enrolment-capability";

struct RootAccess {
    authenticator: SoftToken,
    user: String,
    credential: Vec<u8>,
}

/// One running Global and its single operator Root, enrolled at most once.
struct Global {
    base: String,
    door: Door,
    clock: Arc<TestClock>,
    root: tokio::sync::Mutex<Option<RootAccess>>,
}

static BY_BASE: LazyLock<Mutex<HashMap<String, Arc<Global>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static BY_ISSUER: LazyLock<Mutex<HashMap<Vec<u8>, Arc<Global>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl Global {
    fn running(&self) -> Running {
        Running {
            base: self.base.clone(),
            door: self.door.clone(),
            clock: self.clock.clone(),
            task: tokio::spawn(async {}),
            dir: tempfile::tempdir().unwrap(),
        }
    }
    /// A fresh Root session; the operator enrols once and signs in afterwards.
    async fn root_session(&self, running: &Running) -> (String, String, Vec<u8>) {
        let mut guard = self.root.lock().await;
        if let Some(root) = guard.as_mut() {
            let session = login(
                running,
                ROOT,
                &mut root.authenticator,
                &root.user,
                &root.credential,
            )
            .await;
            return (session, root.user.clone(), root.credential.clone());
        }
        let member = enrol_raw(running, ROOT, Some(OPERATOR_CAPABILITY)).await;
        let result = (
            member.session.clone(),
            member.user.clone(),
            member.credential.clone(),
        );
        *guard = Some(RootAccess {
            authenticator: member.authenticator,
            user: member.user,
            credential: member.credential,
        });
        result
    }
}

pub async fn register(service: &Running) {
    let config = std::fs::read(service.dir.path().join("issuer")).unwrap();
    let issuer = cpsd::IssuerKey::from_secret_bytes(&config)
        .unwrap()
        .public_key()
        .to_bytes();
    let global = Arc::new(Global {
        base: service.base.clone(),
        door: service.door.clone(),
        clock: service.clock.clone(),
        root: tokio::sync::Mutex::new(None),
    });
    BY_BASE
        .lock()
        .unwrap()
        .insert(service.base.clone(), global.clone());
    BY_ISSUER.lock().unwrap().insert(issuer, global);
}

pub fn is_registered(service: &Running) -> bool {
    BY_BASE.lock().unwrap().contains_key(&service.base)
}

/// The operator Root as a test member: a fresh genuine session of the single
/// enrolled passkey. The returned authenticator is a placeholder; use
/// `relogin_root` for another sign-in.
pub async fn root_member(service: &Running, _bootstrap: Option<&str>) -> Member {
    let global = BY_BASE.lock().unwrap().get(&service.base).cloned().unwrap();
    let (session, user, credential) = global.root_session(service).await;
    Member {
        authenticator: SoftToken::new(true).unwrap().0,
        user,
        credential,
        session,
        signing_key: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
    }
}

/// Another genuine Root session for a registered Global.
pub async fn relogin_root(service: &Running) -> String {
    root_member(service, None).await.session
}

/// Link `running` as the community `name` of the Global behind `public`, let the
/// registered `member` prepare as recipient and let the Global Root issue the
/// one-use first-Root entitlement. The member redeems it with its own full-gate
/// admission flow (`creation` in `credential_issue`). None when unregistered.
pub async fn creation_invitation(
    running: &Running,
    name: &str,
    public: &GlobalPublic,
    member: &Member,
) -> Option<Vec<u8>> {
    let global = BY_ISSUER.lock().unwrap().get(&public.issuer).cloned()?;
    let platform = global.running();
    platform
        .door
        .link_community_creation(&running.door)
        .await
        .unwrap();
    let (root, _, _) = global.root_session(&platform).await;
    let host = format!("api.{name}.{DOMAIN}");
    let api = client(running, &host, Some(&member.session));
    let prepared: CreationRecipient = serde_json::from_value(
        api.call(
            "community_creation_recipient",
            json!({"id":null,"expires_at":running.clock.now() + 300,"purpose":"root"}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let created: CommunityCreationInvitation = serde_json::from_value(
        client(&platform, ROOT, Some(&root))
            .call(
                "community_creation_initialize",
                json!({"community":name,"recipient":prepared.recipient}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    Some(created.invitation)
}

/// Found `running` as the community `name` of the Global behind `public`.
/// A Global that is not registered leaves the community unfounded.
pub async fn found(running: &Running, name: &str, public: &GlobalPublic) {
    let Some(global) = BY_ISSUER.lock().unwrap().get(&public.issuer).cloned() else {
        return;
    };
    let platform = global.running();
    let (_, passport, _) = wallet_passport(&platform).await;
    let host = format!("api.{name}.{DOMAIN}");
    let founder = enrol_community(running, &host, &passport).await;
    let invitation = creation_invitation(running, name, public, &founder)
        .await
        .unwrap();
    let api = client(running, &host, Some(&founder.session));
    api.call("handle_reserve", json!({"handle":"founding_root"}))
        .await
        .unwrap();
    let subject = passport
        .pseudonym(&cpsd::CommunityId::new(name).unwrap())
        .to_hex();
    api.voucher_redeem(voucher(
        name,
        &subject,
        "founding-full-gate",
        running.clock.now() + 172_800,
    ))
    .await
    .unwrap();
    let proof = presentation(running, &host, Some(&founder.session), &passport).await;
    api.call(
        "credential_issue",
        json!({"presentation":proof,"devices":[founder.signing_key],"creation":invitation}),
    )
    .await
    .unwrap();
}
