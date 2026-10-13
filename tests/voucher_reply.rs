#![cfg(feature = "development-gate")]
mod support;
use serde_json::json;
use support::*;

/// The relay takes a sealed reply on the link's management secret alone (no
/// session, so it never learns which member issued the link) and gives it only
/// to the member who redeemed the link.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_takes_a_reply_without_a_session_and_only_its_member_reads_it() {
    let global = global(100).await;
    let (_, _, public) = wallet_passport(&global).await;
    let community = community("relay", &public).await;
    let host = "api.relay.example.test";
    let (_, first_passport, _) = wallet_passport(&global).await;
    let (_, second_passport, _) = wallet_passport(&global).await;
    let first = admitted_community_member(&community, "relay", &first_passport, "relay_first").await;
    let second =
        admitted_community_member(&community, "relay", &second_passport, "relay_second").await;
    let subject = |passport: &cpsd::Passport| {
        passport
            .pseudonym(&cpsd::CommunityId::new("relay").unwrap())
            .to_hex()
    };
    // The link the second member redeemed, rebuilt from its fixture id.
    let link = voucher(
        "relay",
        &subject(&second_passport),
        "relay_second",
        NOW + 172_800,
    );
    let sealed = "ab".repeat(48);
    let post = json!({
        "id": link["manage"]["id"],
        "secret": link["manage"]["secret"],
        "member": subject(&second_passport),
        "reply": sealed,
    });
    // No Authorization header: the management secret is the only authority.
    assert_eq!(
        call_status(&community, host, None, "voucher_reply_post", post.clone()).await,
        200
    );
    // A wrong management secret is refused.
    let mut forged = post.clone();
    forged["secret"] = json!("00".repeat(32));
    assert_ne!(
        call_status(&community, host, None, "voucher_reply_post", forged).await,
        200
    );
    let read = json!({"id": link["redeem"]["id"], "secret": link["redeem"]["secret"]});
    // The redeeming member reads it.
    let own = client(&community, host, Some(&second.session))
        .call("voucher_reply_get", read.clone())
        .await
        .unwrap();
    assert_eq!(own["reply"], sealed);
    // A different member holding the same link text still gets nothing.
    let other = client(&community, host, Some(&first.session))
        .call("voucher_reply_get", read.clone())
        .await;
    assert!(other.map(|value| value["reply"].is_null()).unwrap_or(true));
    // Without a session the read is refused.
    assert_ne!(
        call_status(&community, host, None, "voucher_reply_get", read).await,
        200
    );
}
