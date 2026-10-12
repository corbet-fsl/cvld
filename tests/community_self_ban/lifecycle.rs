use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permanent_self_ban_immediately_publishes_the_epoch_that_refuses_an_actual_issued_bundle() {
    let global = global(200).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = member(&service, HOST, &passport).await;
    let bundle = admitted_bundle(&service, &mut owner, &passport).await;
    let before = feed(&service).await;
    assert!(
        guard(&bundle, &before).is_admitted(),
        "the genuine pre-ban credential/profile bundle must actually pass the guard"
    );
    let pending = challenge(&service, &owner).await;
    let body = answer(&mut owner, pending).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body.clone()
        )
        .await,
        200
    );
    let after = feed(&service).await;
    assert!(
        after.policy_epoch > before.policy_epoch,
        "successful termination must publish revocation before returning"
    );
    match guard(&bundle, &after) {
        cgrd::Admission::Refused { reasons } => assert!(
            reasons.contains(&cgrd::Refusal::Version) || reasons.contains(&cgrd::Refusal::Revoked)
        ),
        _ => panic!("an actually issued pre-ban bundle must not remain admitted"),
    }
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "lobby",
            json!({})
        )
        .await,
        401
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
        401
    );
    let proof = presentation(&service, HOST, None, &passport).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            None,
            "register_begin",
            json!({"passport":proof})
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &global,
            WALLET,
            Some(&wallet.session),
            "passport_challenge",
            json!({})
        )
        .await,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_membership_can_terminate_without_linking_or_ending_another_community() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let alpha = community("alpha", &public).await;
    let beta = community("beta", &public).await;
    let mut owner = member(&alpha, HOST, &passport).await;
    let other = member(&beta, "api.beta.example.test", &passport).await;
    let alpha_lobby: Lobby = serde_json::from_value(
        client(&alpha, HOST, Some(&owner.session.token))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let beta_lobby: Lobby = serde_json::from_value(
        client(&beta, "api.beta.example.test", Some(&other.session.token))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_ne!(alpha_lobby.member_id, beta_lobby.member_id);
    let before = feed(&alpha).await;
    let pending = challenge(&alpha, &owner).await;
    let body = answer(&mut owner, pending).await;
    assert_eq!(
        call_status(
            &alpha,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        200
    );
    assert!(feed(&alpha).await.policy_epoch > before.policy_epoch);
    assert_eq!(
        call_status(
            &beta,
            "api.beta.example.test",
            Some(&other.session.token),
            "lobby",
            json!({})
        )
        .await,
        200
    );
    let proof = presentation(&alpha, HOST, None, &passport).await;
    assert_eq!(
        call_status(
            &alpha,
            HOST,
            None,
            "register_begin",
            json!({"passport":proof})
        )
        .await,
        409
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_authorizing_passkey_publishes_its_exact_id_and_only_a_surviving_key_can_self_ban()
 {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = member(&service, HOST, &passport).await;
    let bundle = admitted_bundle(&service, &mut owner, &passport).await;
    assert!(guard(&bundle, &feed(&service).await).is_admitted());
    let pending = challenge(&service, &owner).await;
    let self_ban = answer(&mut owner, pending).await;
    let api = client(&service, HOST, Some(&owner.session.token));
    let proof = owner
        .device
        .step_up(
            &service,
            HOST,
            &owner.session.token,
            json!({"kind":"passkey_add"}),
        )
        .await;
    let begin: AddedPasskey = serde_json::from_value(
        api.call("passkey_add", json!({"step":"begin","step_up":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = begin
    else {
        panic!("fresh additional registration")
    };
    let mut survivor = Resident::default();
    let mut credential = survivor
        .ceremony(options, true, &format!("https://{HOST}"))
        .await;
    strip_prf(&mut credential);
    api.call(
        "passkey_add",
        json!({"step":"finish","ceremony":ceremony,"credential":credential}),
    )
    .await
    .unwrap();
    let survivor_session = discover(&service, HOST, &mut survivor).await;
    let proof = survivor
        .step_up(
            &service,
            HOST,
            &survivor_session.token,
            json!({"kind":"passkey_revoke","credential":owner.credential}),
        )
        .await;
    client(&service, HOST, Some(&survivor_session.token))
        .call(
            "passkey_revoke",
            json!({"credential":owner.credential,"step_up":proof}),
        )
        .await
        .unwrap();
    let after = feed(&service).await;
    assert!(
        revocations(&after).passkeys.contains(&owner.credential),
        "signed publications must preserve the original revoked passkey ID"
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_finish",
            self_ban
        )
        .await,
        401
    );
    assert!(!guard(&bundle, &after).is_admitted());
    let mut survivor = Member {
        device: survivor,
        session: survivor_session,
        credential: Vec::new(),
    };
    let pending = challenge(&service, &survivor).await;
    let body = answer(&mut survivor, pending).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&survivor.session.token),
            "community_self_ban_finish",
            body
        )
        .await,
        200
    );
    assert!(feed(&service).await.policy_epoch > after.policy_epoch);
}
