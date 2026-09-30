use crate::{
    fixtures,
    process::{Cli, Result},
};
use cvld::api::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| "unexpected public response shape".into())
}
pub struct Member {
    pub token: SoftToken,
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
    let mut token = SoftToken::new(true)
        .map_err(|_| "software authenticator")?
        .0;
    let options: cpky::CreationChallengeResponse = decode(start.options)?;
    let credential = token
        .perform_register(
            cpky::Url::parse(&format!("https://{}", cli.host)).unwrap(),
            options.public_key,
            300_000,
        )
        .map_err(|_| "software passkey registration")?;
    let credential_id = credential.raw_id.as_ref().to_vec();
    let user: User = decode(cli.call(
        None,
        "register_finish",
        json!({"ceremony":start.ceremony,"credential":credential}),
    )?)?;
    let mut seed = [0; 32];
    cpsd::rand::RngCore::fill_bytes(&mut cpsd::rand::rngs::OsRng, &mut seed);
    let mut member = Member {
        token,
        user: user.user,
        credential: credential_id,
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
    let options: cpky::RequestChallengeResponse = decode(start.options)?;
    let response = member
        .token
        .perform_auth(
            cpky::Url::parse(&format!("https://{}", cli.host)).unwrap(),
            options.public_key,
            300_000,
        )
        .map_err(|_| "software passkey authentication")?;
    let session: Session = decode(cli.call(
        None,
        "login_finish",
        json!({"ceremony":start.ceremony,"credential":response}),
    )?)?;
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
