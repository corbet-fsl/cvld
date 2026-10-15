use super::*;
use crate::{
    community::CommunityClock,
    test_support::{
        NOW, TestClock,
        resident::{Resident, strip_prf},
    },
};
use clbs::Verifier;
use std::sync::atomic::AtomicU64;

const COMMUNITY: &str = "self-ban-authority";
const ORIGIN: &str = "https://members.example.test";
const SUBJECT: &str = "community-pseudonym";
type Membership = cmbr::Membership<cmbr::LibsqlStorage, CommunityAuthority, CommunityClock>;

struct Fixture {
    _directory: tempfile::TempDir,
    db: crlt::Db,
    clock: Arc<TestClock>,
    authority: CommunityAuthority,
    membership: Membership,
    device: Resident,
    auth: ckyh::Authentication,
}
fn order(id: &str) -> clbs::Order {
    clbs::Order {
        community: COMMUNITY.into(),
        id: id.into(),
        subject: SUBJECT.into(),
        reference: "member-confirmed-termination".into(),
        entered_by: SUBJECT.into(),
        kind: clbs::OrderKind::SelfBan,
    }
}
impl Fixture {
    async fn new(capacity: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let db = crlt::Db::open(crlt::Config::new(
            format!(
                "file://{}",
                directory.path().join("membership.db").display()
            ),
            "",
        ))
        .await
        .unwrap();
        let migrations: Vec<_> = cmbr::SCHEMAS
            .iter()
            .chain([&("device-registry", cmbr::DEVICE_REGISTRY_SCHEMA)])
            .enumerate()
            .map(|(index, (name, sql))| crlt::Migration::new(index as u32 + 1, name, sql))
            .collect();
        db.migrate(&migrations).await.unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
        let authority = CommunityAuthority::new(COMMUNITY, clock.clone(), capacity).unwrap();
        let membership = cmbr::Membership::new(
            &db,
            cmbr::LibsqlStorage::new(&db, COMMUNITY).unwrap(),
            cmbr::Config {
                pending_days: 2,
                membership_action: "membership".into(),
                release_period: Default::default(),
                lease_months: 12,
                rp_id: "members.example.test".into(),
                origins: vec![ckyh::Url::parse(ORIGIN).unwrap()],
            },
            authority.clone(),
            CommunityClock(clock.clone()),
        )
        .unwrap();
        let mut device = Resident::default();
        let user = ckyh::Uuid::new_v4();
        let (challenge, pending) = membership.begin_registration(user, SUBJECT).await.unwrap();
        let mut response = device
            .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
            .await;
        strip_prf(&mut response);
        membership
            .finish_registration(pending, serde_json::from_value(response).unwrap())
            .await
            .unwrap();
        let (challenge, pending) = membership.begin_discoverable_login().await.unwrap();
        let mut response = device
            .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
            .await;
        strip_prf(&mut response);
        let auth = membership
            .finish_login(pending, serde_json::from_value(response).unwrap())
            .await
            .unwrap()
            .authentication;
        Self {
            _directory: directory,
            db,
            clock,
            authority,
            membership,
            device,
            auth,
        }
    }
    async fn confirmation(&mut self, id: &str, expiry: u64) -> cmbr::ConfirmedSelfBan {
        let (challenge, pending) = self
            .membership
            .begin_self_ban_confirmation(&self.auth, order(id), expiry as i64)
            .await
            .unwrap();
        let mut response = self
            .device
            .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
            .await;
        strip_prf(&mut response);
        self.membership
            .finish_self_ban_confirmation(
                &self.auth,
                pending,
                serde_json::from_value(response).unwrap(),
            )
            .await
            .unwrap()
    }
    fn gate(&self) -> clbs::Gate<cmty::cgts::legal_storage::LibsqlStore, CommunityAuthority> {
        clbs::Gate::new(
            cmty::cgts::legal_storage::LibsqlStore::new(&self.db, COMMUNITY).unwrap(),
            self.authority.clone(),
        )
    }
}
fn copy(order: &clbs::SignedOrder) -> clbs::SignedOrder {
    clbs::SignedOrder {
        order: order.order.clone(),
        proof: order.proof.clone(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn real_confirmation_records_permanent_self_ban_once_and_releases_membership() {
    let mut f = Fixture::new(2).await;
    let confirmation = f.confirmation("termination", NOW + 60).await;
    let signed = f.authority.authorize(confirmation).await.unwrap();
    let replay = copy(&signed);
    let row = f.membership.self_ban(&f.auth, &signed).await.unwrap();
    assert_eq!(row.state(), cmbr::State::Released);
    let gate = f.gate();
    assert_eq!(
        gate.record("termination").await.unwrap().unwrap().order(),
        &signed.order
    );
    assert!(matches!(
        gate.check(SUBJECT).await.unwrap(),
        clbs::State::Red(_)
    ));
    assert_eq!(gate.self_ban(&replay).await, Err(clbs::Error::Denied));
    assert_eq!(gate.counts().await.unwrap().self_bans, 1);
    assert!(f.membership.resume(&f.auth).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn every_immutable_order_field_is_bound_and_tampering_consumes_the_capability() {
    let mut f = Fixture::new(2).await;
    for field in 0..6 {
        let confirmation = f.confirmation(&format!("bound-{field}"), NOW + 60).await;
        let signed = f.authority.authorize(confirmation).await.unwrap();
        let mut changed = copy(&signed);
        match field {
            0 => changed.order.community = "other".into(),
            1 => changed.order.id.push('x'),
            2 => changed.order.subject.push('x'),
            3 => changed.order.reference.push('x'),
            4 => changed.order.entered_by.push('x'),
            5 => {
                changed.order.kind = clbs::OrderKind::Legal {
                    authority: "court".into(),
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.authority.verify_self_ban(&changed).await,
            Err(clbs::Error::Denied)
        );
        assert_eq!(
            f.authority.verify_self_ban(&signed).await,
            Err(clbs::Error::Denied)
        );
    }
    assert_eq!(f.gate().counts().await.unwrap().self_bans, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_are_bounded_expiring_community_bound_and_not_legal_authority() {
    let mut f = Fixture::new(1).await;
    let confirmation = f.confirmation("wrong-authority", NOW + 60).await;
    let foreign = CommunityAuthority::new("other", f.clock.clone(), 1).unwrap();
    assert!(matches!(
        foreign.authorize(confirmation).await,
        Err(Error::Unauthorized)
    ));
    let confirmation = f.confirmation("first", NOW + 1).await;
    let first = f.authority.authorize(confirmation).await.unwrap();
    let confirmation = f.confirmation("over-capacity", NOW + 60).await;
    assert!(matches!(
        f.authority.authorize(confirmation).await,
        Err(Error::Throttled)
    ));
    assert_eq!(
        foreign.verify_self_ban(&first).await,
        Err(clbs::Error::Denied)
    );
    assert_eq!(
        f.authority.verify_legal(&first).await,
        Err(clbs::Error::Denied)
    );
    f.clock.set(NOW + 1);
    assert_eq!(
        f.authority.verify_self_ban(&first).await,
        Err(clbs::Error::Denied)
    );
    let confirmation = f.confirmation("next", NOW + 60).await;
    let next = f.authority.authorize(confirmation).await.unwrap();
    assert!(f.authority.verify_self_ban(&next).await.is_ok());
    let confirmation = f
        .confirmation("expires-before-authorization", NOW + 60)
        .await;
    f.clock.set(NOW + 60);
    assert!(matches!(
        f.authority.authorize(confirmation).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.gate().counts().await.unwrap().self_bans, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn live_clock_expires_authority_even_inside_a_frozen_operation() {
    let mut f = Fixture::new(1).await;
    let confirmation = f.confirmation("live-clock", NOW + 1).await;
    let signed = f.authority.authorize(confirmation).await.unwrap();
    f.clock.set(NOW + 1);
    crate::service::at(NOW, async {
        assert_eq!(f.gate().self_ban(&signed).await, Err(clbs::Error::Denied));
    })
    .await;
    assert_eq!(f.gate().counts().await.unwrap().self_bans, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_or_replayed_proofs_never_create_a_restriction() {
    let mut f = Fixture::new(1).await;
    for proof in [Vec::new(), vec![0; 64], b"not-a-confirmation".to_vec()] {
        assert!(
            f.gate()
                .self_ban(&clbs::SignedOrder {
                    order: order("forged"),
                    proof
                })
                .await
                .is_err()
        );
    }
    let confirmation = f.confirmation("concurrent", NOW + 60).await;
    let signed = f.authority.authorize(confirmation).await.unwrap();
    let replay = copy(&signed);
    let (first, second) = tokio::join!(
        f.authority.verify_self_ban(&signed),
        f.authority.verify_self_ban(&replay)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(f.gate().counts().await.unwrap().self_bans, 0);
}
