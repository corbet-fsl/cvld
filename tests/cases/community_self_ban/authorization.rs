use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_login_wrong_sessions_roles_hosts_and_caller_targets_cannot_authorize_termination()
{
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = member(&service, HOST, &passport).await;
    let secondary = discover(&service, HOST, &mut owner.device).await;
    let root = enrol(&service, ROOT, Some("synthetic-root-enrolment-capability")).await;
    let admin_host = "api.admin.alpha.example.test";
    let (_, admin_passport, _) = wallet_passport(&global).await;
    let mut admin =
        admitted_community_member(&service, "alpha", &admin_passport, "termination_admin").await;
    let admin_subject = admin_passport
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    preexisting_role(&service, "alpha", &admin_subject, crgs::Role::Admin).await;
    admin.session = login(
        &service,
        admin_host,
        &mut admin.authenticator,
        &admin.user,
        &admin.credential,
    )
    .await;
    let before = feed(&service).await;
    assert_eq!(
        call_status(&service, HOST, None, "community_self_ban_begin", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&root.session),
            "community_self_ban_begin",
            json!({})
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &service,
            "api.beta.example.test",
            Some(&owner.session.token),
            "community_self_ban_begin",
            json!({})
        )
        .await,
        421
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_begin",
            json!({"subject":"another-member"})
        )
        .await,
        400
    );
    let login: DiscoverableCeremony = serde_json::from_value(
        client(&service, HOST, None)
            .call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call_status(
            &service,
            admin_host,
            Some(&admin.session),
            "community_self_ban_begin",
            json!({})
        )
        .await,
        403
    );
    let pending = challenge(&service, &owner).await;
    let mut credential = owner
        .device
        .ceremony(login.options, false, &format!("https://{HOST}"))
        .await;
    strip_prf(&mut credential);
    let body = json!({"ceremony":pending.ceremony,"credential":credential});
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        409
    );
    assert_eq!(feed(&service).await.policy_epoch, before.policy_epoch);
    // Replacing a ceremony affects only its originating session.
    let obsolete = challenge(&service, &owner).await;
    let current = challenge(&service, &owner).await;
    let body = answer(&mut owner, obsolete).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        401
    );
    let body = answer(&mut owner, current).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&secondary.token),
            "community_self_ban_finish",
            body.clone()
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&root.session),
            "community_self_ban_finish",
            body.clone()
        )
        .await,
        403
    );
    let mut target = body.clone();
    assert_eq!(
        call_status(
            &service,
            admin_host,
            Some(&admin.session),
            "community_self_ban_finish",
            body.clone()
        )
        .await,
        403
    );
    target["subject"] = json!("another-member");
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            target
        )
        .await,
        400
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        200
    );
    assert_eq!(
        call_status(&service, HOST, Some(&secondary.token), "lobby", json!({})).await,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_and_exclusive_deadline_cancel_pending_confirmation_without_a_public_revocation() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = member(&service, HOST, &passport).await;
    let before = feed(&service).await;
    let pending = challenge(&service, &owner).await;
    let body = answer(&mut owner, pending).await;
    client(&service, HOST, Some(&owner.session.token))
        .call("logout", json!({}))
        .await
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        401
    );
    owner.session = discover(&service, HOST, &mut owner.device).await;
    let pending = challenge(&service, &owner).await;
    let expires = pending.expires;
    let body = answer(&mut owner, pending).await;
    service.clock.set(expires);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        401
    );
    assert_eq!(feed(&service).await.policy_epoch, before.policy_epoch);
    assert!(revocations(&feed(&service).await).members.is_empty());
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "lobby",
            json!({})
        )
        .await,
        200
    );
}
