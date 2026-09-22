//! Thin browser binding to the existing AnonCreds implementation.
//! The holder's link secret and request metadata never cross the server API.
use anoncreds::{prover, verifier};
use anoncreds::types::{Credential, CredentialOffer, CredentialRequestMetadata,
    LinkSecret, PresentCredentials, Presentation, PresentationRequest};
use anoncreds::data_types::{cred_def::{CredentialDefinition, CredentialDefinitionId}, schema::{Schema, SchemaId}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

const MAX_JSON_BYTES: usize = 1_048_576;
fn rejected() -> JsValue { JsValue::from_str("Credential operation rejected") }
fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, JsValue> {
    if text.len() > MAX_JSON_BYTES { return Err(rejected()); }
    serde_json::from_str(text).map_err(|_| rejected())
}
fn wire<T: Serialize>(value: &T) -> Result<String, JsValue> {
    let text = serde_json::to_string(value).map_err(|_| rejected())?;
    if text.len() > MAX_JSON_BYTES { return Err(rejected()); }
    Ok(text)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicIssuer {
    schema_id: SchemaId,
    credential_definition_id: CredentialDefinitionId,
    schema: Schema,
    credential_definition: CredentialDefinition,
}

/// The browser owns this handle. Run proving in a dedicated Worker.
#[wasm_bindgen]
pub struct BrowserCredential {
    secret: LinkSecret,
    metadata: Option<CredentialRequestMetadata>,
    credential: Option<Credential>,
}

#[wasm_bindgen]
impl BrowserCredential {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BrowserCredential, JsValue> {
        Ok(Self { secret: prover::create_link_secret().map_err(|_| rejected())?,
            metadata: None, credential: None })
    }

    /// Returns only the blinded public request. Metadata stays with this handle.
    pub fn request(&mut self, issuer_json: &str, offer_json: &str, entropy: &str) -> Result<String, JsValue> {
        if self.metadata.is_some() || self.credential.is_some() || entropy.len() < 32 || entropy.len() > 128 {
            return Err(rejected());
        }
        let issuer: PublicIssuer = parse(issuer_json)?;
        let offer: CredentialOffer = parse(offer_json)?;
        if offer.schema_id != issuer.schema_id || offer.cred_def_id != issuer.credential_definition_id { return Err(rejected()); }
        let (request, metadata) = prover::create_credential_request(Some(entropy), None,
            &issuer.credential_definition, &self.secret, "cvld-wallet", &offer).map_err(|_| rejected())?;
        let result = wire(&request)?;
        self.metadata = Some(metadata);
        Ok(result)
    }

    /// Check the issuer's credential signature before retaining the credential.
    pub fn accept(&mut self, issuer_json: &str, credential_json: &str) -> Result<(), JsValue> {
        if self.credential.is_some() { return Err(rejected()); }
        let issuer: PublicIssuer = parse(issuer_json)?;
        let mut credential: Credential = parse(credential_json)?;
        if credential.schema_id != issuer.schema_id || credential.cred_def_id != issuer.credential_definition_id
            || credential.rev_reg_id.is_some() { return Err(rejected()); }
        let metadata = self.metadata.as_ref().ok_or_else(rejected)?;
        prover::process_credential(&mut credential, metadata, &self.secret,
            &issuer.credential_definition, None).map_err(|_| rejected())?;
        self.credential = Some(credential);
        self.metadata = None;
        Ok(())
    }

    /// Only the fixed private profile disclosure is accepted here. Member ID,
    /// link secret and exact validity never become revealed attributes.
    #[wasm_bindgen(js_name = presentProfile)]
    pub fn present_profile(&self, issuer_json: &str, request_json: &str) -> Result<String, JsValue> {
        let issuer: PublicIssuer = parse(issuer_json)?;
        let raw: serde_json::Value = parse(request_json)?;
        let nonce = raw.get("nonce").and_then(|v| v.as_str()).ok_or_else(rejected)?;
        let expiry = raw.pointer("/requested_predicates/valid_until/p_value")
            .and_then(|v| v.as_i64()).filter(|v| *v > 0 && *v <= i32::MAX as i64).ok_or_else(rejected)?;
        let restrictions = serde_json::json!([{"cred_def_id":issuer.credential_definition_id}]);
        // Check names as well as referents: relabeling member_id as "policy"
        // must never trick the holder into disclosing its private account ID.
        let expected = serde_json::json!({"name":"cfrm-profile-key","version":"1","nonce":nonce,
            "requested_attributes":{
                "community_id":{"name":"community_id","restrictions":restrictions},
                "policy":{"name":"policy","restrictions":restrictions}},
            "requested_predicates":{
                "eligible":{"name":"eligible","p_type":">=","p_value":1,"restrictions":restrictions},
                "valid_until":{"name":"valid_until","p_type":">=","p_value":expiry,"restrictions":restrictions}}});
        if raw != expected { return Err(rejected()); }
        let request: PresentationRequest = parse(request_json)?;
        let value = request.value();
        if value.requested_attributes.len() != 2 || value.requested_predicates.len() != 2
            || !value.requested_attributes.contains_key("community_id")
            || !value.requested_attributes.contains_key("policy")
            || !value.requested_predicates.contains_key("eligible")
            || !value.requested_predicates.contains_key("valid_until") { return Err(rejected()); }
        let credential = self.credential.as_ref().ok_or_else(rejected)?;
        let mut credentials = PresentCredentials::default();
        let mut selected = credentials.add_credential(credential, None, None);
        selected.add_requested_attribute("community_id", true);
        selected.add_requested_attribute("policy", true);
        selected.add_requested_predicate("eligible");
        selected.add_requested_predicate("valid_until");
        let schemas = HashMap::from([(issuer.schema_id, issuer.schema)]);
        let definitions = HashMap::from([(issuer.credential_definition_id, issuer.credential_definition)]);
        wire(&prover::create_presentation(&request, credentials, None, &self.secret,
            &schemas, &definitions).map_err(|_| rejected())?)
    }

    /// Private local bytes. The caller must encrypt before persistence; this is
    /// never an API response and contains no issuer-side recovery capability.
    #[wasm_bindgen(js_name = privateState)]
    pub fn private_state(&self) -> Result<String, JsValue> {
        let credential = self.credential.as_ref().ok_or_else(rejected)?;
        let secret: String = self.secret.try_clone().map_err(|_| rejected())?.try_into().map_err(|_| rejected())?;
        wire(&serde_json::json!({"version":1,"linkSecret":secret,"credential":credential}))
    }

    /// Input is decrypted only inside the local holder's trust boundary.
    #[wasm_bindgen(js_name = fromPrivateState)]
    pub fn from_private_state(json: &str) -> Result<BrowserCredential, JsValue> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct State { version: u8, link_secret: String, credential: Credential }
        let state: State = parse(json)?;
        if state.version != 1 || state.link_secret.len() > 1024 || state.link_secret.is_empty()
            || !state.link_secret.bytes().all(|b| b.is_ascii_digit()) { return Err(rejected()); }
        Ok(Self { secret: LinkSecret::try_from(state.link_secret.as_str()).map_err(|_| rejected())?,
            metadata: None, credential: Some(state.credential) })
    }
}

/// Public proof verification using the same independently pinned issuer data.
#[wasm_bindgen(js_name = verifyProfilePresentation)]
pub fn verify_profile_presentation(issuer_json: &str, request_json: &str, proof_json: &str) -> Result<bool, JsValue> {
    let issuer: PublicIssuer = parse(issuer_json)?;
    let request: PresentationRequest = parse(request_json)?;
    let proof: Presentation = parse(proof_json)?;
    let schemas = HashMap::from([(issuer.schema_id, issuer.schema)]);
    let definitions = HashMap::from([(issuer.credential_definition_id, issuer.credential_definition)]);
    verifier::verify_presentation(&proof, &request, &schemas, &definitions, None, None, None).map_err(|_| rejected())
}
