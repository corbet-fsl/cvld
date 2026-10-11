use super::*;
use crate::error::ErrorBody;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_http_clock_change_withholds_the_real_answer_and_keeps_the_context_burned() {
    let mut final_sample = 0;
    for advance in [false, true] {
        let mut world = world().await;
        let garden = client(&world.source, GARDEN, Some(&world.garden));
        let challenge: RootBoardIssueChallenge = serde_json::from_value(
            garden
                .call("root_board_issue_begin", json!({}))
                .await
                .unwrap(),
        )
        .unwrap();
        let source = anchor(&world.source, SOURCE, "alpha").await;
        let root = anchor(&world.root, ROOT_MEMBER, "root").await;
        let request = world
            .holder
            .begin_root_board_issuance(
                &mut cpsd::rand::rngs::OsRng,
                &root,
                &challenge.signed_context,
                &source,
                &challenge.signed_source_request,
                NOW,
            )
            .unwrap();
        let body = json!({"challenge":challenge.challenge,"proof":request.to_bytes()});
        // The first genuine HTTP/SQL/CPSD round trip measures the final root
        // clock observation. The second advances ONLY at that same release
        // cut, after successful original issuance and before exposing bytes.
        world.root_clock.samples.store(0, Ordering::SeqCst);
        if advance {
            world
                .root_clock
                .advance_at
                .store(final_sample, Ordering::SeqCst);
        }
        let response = reqwest::Client::new()
            .post(format!("{}/v1/root_board_issue_finish", world.source.base))
            .header("host", GARDEN)
            .bearer_auth(&world.garden)
            .json(&body)
            .send()
            .await
            .unwrap();
        if !advance {
            assert_eq!(response.status().as_u16(), 200);
            let answer: Bytes = response.json().await.unwrap();
            world
                .holder
                .finish_root_board_issuance(
                    &cpsd::BlindRootBoardCredential::from_bytes(&answer.bytes).unwrap(),
                )
                .unwrap();
            final_sample = world.root_clock.samples.load(Ordering::SeqCst);
            assert!(final_sample > 1);
        } else {
            assert_eq!(response.status().as_u16(), 503);
            let refused: ErrorBody = response.json().await.unwrap();
            assert!(matches!(refused.error, Error::Reconcile));
            assert_eq!(
                world.root_clock.samples.load(Ordering::SeqCst),
                final_sample
            );
            assert_eq!(world.root.clock.now(), NOW + 1);
            assert!(garden.call("root_board_issue_finish", body).await.is_err());
        }
    }
}
