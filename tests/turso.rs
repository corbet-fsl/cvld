#[tokio::test(flavor = "multi_thread")]
async fn optional_real_turso() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        return;
    };
    if url.is_empty() || token.is_empty() {
        return;
    }
    // Supply a disposable database only. Public CI configures neither value.
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "global", cglb::storage::SCHEMA)])
        .await
        .unwrap();
    let store = cglb::storage::LibsqlStore::new(&db, "cvld-disposable-test").unwrap();
    store.check_query_plans().await.unwrap();
}
