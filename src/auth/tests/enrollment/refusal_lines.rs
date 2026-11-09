//! A refused global `initial_creation` names the check that refused it (journey row 13,
//! 2026-11-09), in one line without the token, the member's UUID or the session id.
use super::*;
use crate::refusal::{
    scope,
    tests::{assert_shape, taken},
};

async fn refused(auth: &mut Auth, token: &str, admitted_at: u64, clock_at: u64) -> String {
    taken();
    let clock = TestClock(AtomicU64::new(clock_at));
    let result = scope(
        "initial_creation",
        auth.initial_creation(token, None, admitted_at, &clock),
    )
    .await;
    assert!(matches!(result, Err(Error::Unauthorized)));
    let lines = taken();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = lines.into_iter().next().unwrap();
    assert_shape(&line);
    assert!(!line.contains(token), "{line}");
    line
}

// The passkey store needs a multi-thread runtime; the body (and so every line) still runs on this thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_global_refusal_names_its_check_and_no_secret() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let session = seeded(&mut auth, &mut Resident::default()).await;
    let token = session.token.clone();
    let cases = [
        // (admitted at, clock at, reason, the grant's ids named); the last one prunes the session.
        (NOW, NOW - 1, "clock_behind", false),
        (NOW, NOW + 600, "session_expired", false),
        (NOW + 601, NOW + 601, "session_expired", true),
        (NOW + 600, NOW + 600, "session_expired", true),
    ];
    for (admitted_at, clock_at, reason, ids) in cases {
        let line = refused(&mut auth, &token, admitted_at, clock_at).await;
        assert!(line.contains(&format!("reason={reason} ")), "{line}");
        assert_eq!(!line.contains("member=-"), ids, "{line}");
        assert!(!line.contains(&session.user), "{line}");
        assert!(!line.contains(&session.user.replace('-', "")), "{line}");
    }
    let line = refused(&mut auth, "never-issued-token", NOW, NOW).await;
    assert!(
        line.contains("reason=session_missing member=- session=-"),
        "{line}"
    );
    auth.logout(&token);
    let line = refused(&mut auth, &token, NOW, NOW).await;
    assert!(line.contains("reason=session_missing "), "{line}");
}
