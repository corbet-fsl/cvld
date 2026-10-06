#![cfg(feature = "development-gate")]
//! Genuine registration, admission and current role checks over the HTTP door.
//! A pre-existing register role is seeded below; this is not root bootstrap.
mod support;
use cvld::api::{Lobby, MemberRole, Role};
use serde_json::json;
use support::*;

const HOST: &str = "api.alpha.example.test";

async fn admit(service: &Running, passport: &cpsd::Passport, handle: &str) -> (Member, String) {
    let member = enrol_community(service, HOST, passport).await;
    let api = client(service, HOST, Some(&member.session));
    // Registration alone never grants a register role.
    assert_eq!(
        call_status(
            service,
            HOST,
            Some(&member.session),
            "member_role",
            json!({})
        )
        .await,
        409
    );
    let lobby: Lobby = serde_json::from_value(
        api.call("handle_reserve", json!({"handle":handle}))
            .await
            .unwrap(),
    )
    .unwrap();
    api.call(
        "gate_voucher",
        voucher("alpha", &lobby.member_id, handle, NOW + 86400),
    )
    .await
    .unwrap();
    assert!(
        issue_community(service, HOST, &member, passport)
            .await
            .credential
            .is_some()
    );
    (member, lobby.member_id)
}

async fn read_role(service: &Running, member: &Member) -> MemberRole {
    serde_json::from_value(
        client(service, HOST, Some(&member.session))
            .call("member_role", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn member_role_actions_follow_current_register_authority() {
    let global = global(100).await;
    let (_, root_passport, public) = wallet_passport(&global).await;
    let (_, admin_passport, _) = wallet_passport(&global).await;
    let (_, member_passport, _) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let (root, root_id) = admit(&service, &root_passport, "root_member").await;
    let (admin, admin_id) = admit(&service, &admin_passport, "admin_member").await;
    let (member, member_id) = admit(&service, &member_passport, "ordinary_member").await;
    assert_eq!(read_role(&service, &root).await.role, Role::Member);
    assert_eq!(read_role(&service, &member).await.member, member_id);
    let change = |target: &str, role: &str| json!({"member":target,"role":role});
    assert_eq!(
        call_status(&service, HOST, None, "member_role", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "member_role_set",
            change(&member_id, "root")
        )
        .await,
        409
    );

    // Establish an existing Root through the original register, after genuine
    // admission. No synthetic membership, passkey or issuance proof is used.
    let db = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            service.dir.path().join("community.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community("alpha").unwrap()),
        crgs::ReleasePeriod::default(),
    );
    register
        .set_role(
            &crgs::MemberId::new(root_id.as_bytes()).unwrap(),
            crgs::Role::Root,
        )
        .await
        .unwrap();
    assert_eq!(read_role(&service, &root).await.role, Role::Root);
    let root_api = client(&service, HOST, Some(&root.session));
    let admin_api = client(&service, HOST, Some(&admin.session));
    root_api
        .call("member_role_set", change(&admin_id, "admin"))
        .await
        .unwrap();
    assert_eq!(read_role(&service, &admin).await.role, Role::Admin);
    admin_api
        .call("member_role_set", change(&member_id, "admin"))
        .await
        .unwrap();
    assert_eq!(read_role(&service, &member).await.role, Role::Admin);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&admin.session),
            "member_role_set",
            change(&root_id, "member")
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&admin.session),
            "member_role_set",
            change(&member_id, "root")
        )
        .await,
        409
    );
    admin_api
        .call("member_role_set", change(&member_id, "member"))
        .await
        .unwrap();
    assert_eq!(read_role(&service, &member).await.role, Role::Member);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&root.session),
            "member_role_set",
            change(&member.user, "root")
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&root.session),
            "member_role_set",
            json!({"member":member_id,"role":"root","actor_role":"root"})
        )
        .await,
        400
    );

    // Existing static operator sessions are never source membership authority.
    let operator_host = "api.admin.alpha.example.test";
    let operator = enrol(
        &service,
        operator_host,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    assert_eq!(
        call_status(
            &service,
            operator_host,
            Some(&operator.session),
            "member_role_set",
            change(&member_id, "admin")
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&operator.session),
            "member_role_set",
            change(&member_id, "admin")
        )
        .await,
        401
    );
    root_api
        .call("member_role_set", change(&admin_id, "member"))
        .await
        .unwrap();
    // A cached session cannot preserve a demoted role.
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&admin.session),
            "member_role_set",
            change(&member_id, "admin")
        )
        .await,
        409
    );
    root_api
        .call("member_role_set", change(&member_id, "root"))
        .await
        .unwrap();
    client(&service, HOST, Some(&member.session))
        .call("member_role_set", change(&root_id, "member"))
        .await
        .unwrap();
    assert_eq!(read_role(&service, &root).await.role, Role::Member);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&root.session),
            "member_role_set",
            change(&admin_id, "root")
        )
        .await,
        409
    );

    // Scope is checked before execution, even for a real global session.
    let outsider = enrol(&global, WALLET, None).await;
    assert_eq!(
        call_status(
            &global,
            WALLET,
            Some(&outsider.session),
            "member_role",
            json!({})
        )
        .await,
        421
    );
    service.clock.set(NOW + 600);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "member_role_set",
            change(&admin_id, "admin")
        )
        .await,
        401
    );
}
