use crate::{
    fixtures,
    process::{Cli, Result},
};
use cvld::api::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
#[path = "../../tests/support/resident.rs"]
mod resident;
use resident::{Resident, strip_prf};

fn passkey_ceremony(
    token: &mut Resident,
    options: Value,
    create: bool,
    host: &str,
) -> (Value, Value) {
    let mut response = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(token.ceremony(
            options,
            create,
            &format!("https://{host}"),
        ))
    });
    let prf = strip_prf(&mut response);
    if create {
        assert_eq!(prf["enabled"], true);
    }
    (response, prf["results"].clone())
}

pub fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| "unexpected public response shape".into())
}
pub struct Member {
    pub token: Resident,
    prf: Value,
    pub user: String,
    pub credential: Vec<u8>,
    pub session: String,
    pub device: [u8; 32],
}
pub fn register(
    cli: &Cli,
    bootstrap: Option<&str>,
    passport: Option<PresentationInput>,
) -> Result<Member> {
    let start: Ceremony = decode(cli.call(
        None,
        "register_begin",
        json!({"bootstrap":bootstrap,"passport":passport}),
    )?)?;
    let mut token = Resident::default();
    let (credential, prf) = passkey_ceremony(&mut token, start.options, true, &cli.host);
    let parsed: ckyh::RegisterPublicKeyCredential = decode(credential.clone())?;
    let credential_id = parsed.raw_id.as_ref().to_vec();
    let user: User = decode(cli.call(
        None,
        "register_finish",
        json!({"ceremony":start.ceremony,"credential":credential}),
    )?)?;
    let mut seed = [0; 32];
    cpsd::rand::RngCore::fill_bytes(&mut cpsd::rand::rngs::OsRng, &mut seed);
    let mut member = Member {
        token,
        prf,
        user: user.user,
        credential: credential_id,
        session: String::new(),
        device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    };
    login(cli, &mut member)?;
    Ok(member)
}
/// Enrol through the same public CLI action available to any authenticated member.
pub fn additional(cli: &Cli, existing: &Member) -> Result<Member> {
    let start: AddedPasskey = decode(cli.call(
        Some(&existing.session),
        "passkey_add",
        json!({"step":"begin"}),
    )?)?;
    let AddedPasskey::Challenge {
        ceremony,
        user,
        options,
    } = start
    else {
        return Err("additional passkey challenge expected".into());
    };
    if user != existing.user {
        return Err("addition changed membership".into());
    }
    let mut token = Resident::default();
    let (response, prf) = passkey_ceremony(&mut token, options, true, &cli.host);
    let parsed: ckyh::RegisterPublicKeyCredential = decode(response.clone())?;
    let credential_id = parsed.raw_id.as_ref().to_vec();
    let result: AddedPasskey = decode(cli.call(
        Some(&existing.session),
        "passkey_add",
        json!({"step":"finish","ceremony":ceremony,"credential":response}),
    )?)?;
    let AddedPasskey::Registered { user, credential } = result else {
        return Err("additional passkey result expected".into());
    };
    if user != existing.user || credential != credential_id {
        return Err("addition changed identity".into());
    }
    let mut seed = [0; 32];
    cpsd::rand::RngCore::fill_bytes(&mut cpsd::rand::rngs::OsRng, &mut seed);
    let mut member = Member {
        token,
        prf,
        user,
        credential,
        session: String::new(),
        device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    };
    login(cli, &mut member)?;
    Ok(member)
}
pub fn login(cli: &Cli, member: &mut Member) -> Result<()> {
    let start: Ceremony = decode(cli.call(
        None,
        "login_begin",
        json!({"user":member.user,"credential":member.credential}),
    )?)?;
    let (response, prf) = passkey_ceremony(&mut member.token, start.options, false, &cli.host);
    if prf != member.prf {
        return Err("passkey PRF changed".into());
    }
    let session: Session = decode(cli.call(
        None,
        "login_finish",
        json!({"ceremony":start.ceremony,"credential":response}),
    )?)?;
    member.session = session.token;
    Ok(())
}
/// Simulate a fresh phone with synced authenticator storage and no saved IDs.
pub fn restore(cli: &Cli, member: &mut Member) -> Result<()> {
    let mut phone = member.token.clone();
    let start: DiscoverableCeremony =
        decode(cli.call(None, "login_discoverable_begin", json!({}))?)?;
    if start.options["publicKey"]["allowCredentials"] != json!([]) {
        return Err("discovery disclosed credentials".into());
    }
    let (response, prf) = passkey_ceremony(&mut phone, start.options, false, &cli.host);
    if prf != member.prf {
        return Err("synced passkey PRF changed".into());
    }
    let session: Session = decode(cli.call(
        None,
        "login_finish",
        json!({"ceremony":start.ceremony,"credential":response}),
    )?)?;
    if session.user != member.user {
        return Err("restore changed membership".into());
    }
    member.token = phone;
    member.session = session.token;
    Ok(())
}
pub struct Wallet {
    pub member: Member,
    pub passport: cpsd::Passport,
}
pub fn wallet(cli: &Cli) -> Result<Wallet> {
    let member = register(cli, None, None)?;
    cli.call(Some(&member.session), "development_gate", json!({}))?;
    let public: GlobalPublic = decode(cli.call(None, "global_public", json!({}))?)?;
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).map_err(|_| "issuer key")?;
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        decode(cli.call(Some(&member.session), "passport_challenge", json!({}))?)?;
    let challenge = cpsd::IssuanceChallenge::from_bytes(
        challenge.bytes.try_into().map_err(|_| "challenge length")?,
    );
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge)
        .map_err(|_| "blind passport request")?;
    let response: Bytes = decode(cli.call(
        Some(&member.session),
        "passport_issue",
        json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
    )?)?;
    let passport = pending
        .finish(&cpsd::BlindPassport::from_bytes(&response.bytes).map_err(|_| "blind passport")?)
        .map_err(|_| "finish passport")?;
    Ok(Wallet { member, passport })
}
pub fn presentation(
    cli: &Cli,
    session: Option<&str>,
    passport: &cpsd::Passport,
    ring: &csgn::KeyRing,
    community: &str,
    now: u64,
) -> Result<PresentationInput> {
    let start: PresentationChallenge =
        decode(cli.call(session, "presentation_challenge", json!({}))?)?;
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(community).map_err(|_| "community")?,
        ring.clone(),
    );
    let proof = passport
        .present(&mut cpsd::rand::rngs::OsRng, &expected, &start.request, now)
        .map_err(|_| "wallet refuses presentation")?;
    Ok(PresentationInput {
        challenge: start.challenge,
        proof: proof.to_bytes(),
    })
}
pub fn voucher(community: &str, member: &str, id: &str, now: u64) -> Value {
    let until = now + 172800;
    let binding = cvch::member_binding(&cvch::receipt_id(id), member.as_bytes());
    let signature = SigningKey::from_bytes(&[9; 32])
        .sign(&cvch::issuance_bytes(id, until, community, &binding))
        .to_bytes()
        .to_vec();
    json!({"id":id,"member_binding":binding,"valid_until":until,"signature":signature})
}
pub fn root(cli: &Cli, global: bool) -> Result<Member> {
    register(
        &cli.host(fixtures::ROOT),
        Some(if global {
            "synthetic-operator-enrolment-capability"
        } else {
            "synthetic-root-enrolment-capability"
        }),
        None,
    )
}
