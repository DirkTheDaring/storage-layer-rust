//! Runs the reusable backend contract suite against the in-memory reference
//! model (`contract::model::ModelObjectStore`). Adapter crates (filesystem,
//! S3) run the SAME suite against their real implementations in later
//! migration phases; this test validates the suite and the contracts
//! themselves.

use naust_storage_core::contract::{self, model::ModelObjectStore};

#[tokio::test]
async fn model_store_satisfies_core_contract_suite() {
    let store = ModelObjectStore::new();
    contract::run_core_suite(&store).await;
}

#[tokio::test]
async fn model_store_individual_checks_run_on_fresh_stores() {
    // Each check is independently runnable against a fresh store — the shape
    // adapter crates will use for focused conformance debugging.
    contract::check_write_then_read(&ModelObjectStore::new()).await;
    contract::check_write_if_absent(&ModelObjectStore::new()).await;
    contract::check_version_observation(&ModelObjectStore::new()).await;
    contract::check_replace_if_version(&ModelObjectStore::new()).await;
    contract::check_delete_idempotent(&ModelObjectStore::new()).await;
    contract::check_delete_if_version(&ModelObjectStore::new()).await;
    contract::check_listing(&ModelObjectStore::new()).await;
    contract::check_read_bound(&ModelObjectStore::new()).await;
    contract::check_dot_prefixed_keys_are_ordinary_objects(&ModelObjectStore::new()).await;
    contract::check_invalid_key_rejection();
}
