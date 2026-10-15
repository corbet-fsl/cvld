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

/// The founder of each founded community (its first admin seat), by service base, until taken.
static FOUNDERS: LazyLock<Mutex<HashMap<String, Member>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The founder of `running` (the community's first admin) with the passkey that founded it, once. It
/// signs in on the admin host with `login`.
pub fn take_founder(running: &Running) -> Option<Member> {
    FOUNDERS.lock().unwrap().remove(&running.base)
}

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

/// A genuine Root sign-in assertion of a registered Global that the caller submits itself (a Foyer
/// or any other client): the user and the `login_finish` body, built with the one enrolled passkey.
pub async fn root_login_request(service: &Running) -> (String, Value) {
    let global = BY_BASE.lock().unwrap().get(&service.base).cloned().unwrap();
    root_member(service, None).await; // enrols the operator on first use
    let mut guard = global.root.lock().await;
    let root = guard.as_mut().unwrap();
    let start: Ceremony = serde_json::from_value(
        client(service, ROOT, None)
            .call(
                "login_begin",
                json!({"user":root.user,"credential":root.credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = root
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(ROOT)).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    (
        root.user.clone(),
        json!({"ceremony":start.ceremony,"credential":credential}),
    )
}

/// Another genuine Root session for a registered Global.
pub async fn relogin_root(service: &Running) -> String {
    root_member(service, None).await.session
}

/// Arm a one-time creator claim on `running` and let the registered `member`
/// claim the first seat. The member redeems the returned creation id with its
/// own full-gate admission flow (`creation` in `credential_issue`). None when
/// the Global is unregistered.
pub async fn creation_invitation(
    running: &Running,
    name: &str,
    public: &GlobalPublic,
    member: &Member,
) -> Option<String> {
    BY_ISSUER.lock().unwrap().get(&public.issuer).cloned()?;
    let secret = b"fixture-creation-claim-secret!!".to_vec();
    running
        .door
        .arm_creation(&secret, running.clock.now() + 300)
        .await
        .unwrap();
    let host = format!("api.{name}.{DOMAIN}");
    let claimed = client(running, &host, Some(&member.session))
        .call("community_creation_claim", json!({ "claim": secret }))
        .await
        .unwrap();
    Some(claimed["id"].as_str().unwrap().to_owned())
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
    FOUNDERS.lock().unwrap().insert(running.base.clone(), founder);
}
