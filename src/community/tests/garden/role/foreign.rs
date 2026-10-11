//! A genuine separately registered key supplies a sealed foreign Authentication.
use super::*;

pub(super) async fn authentication(owner: &CommunityService) -> ckyh::Authentication {
    let user = ckyh::Uuid::new_v4();
    let mut token = SoftToken::new(true).unwrap().0;
    let membership = owner.facade.membership();
    let (mut options, pending) = membership
        .begin_registration(user, &"03".repeat(48))
        .await
        .unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: ckyh::RegisterPublicKeyCredential = token
        .perform_register(
            ckyh::Url::parse(&format!("https://{SOURCE}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap()
        .into();
    let credential = response.raw_id.clone();
    membership
        .finish_registration(pending, response)
        .await
        .unwrap();
    let (options, pending) = membership.begin_login(user, credential).await.unwrap();
    let response = token
        .perform_auth(
            ckyh::Url::parse(&format!("https://{SOURCE}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    membership
        .finish_login(pending, response.into())
        .await
        .unwrap()
        .authentication
}
