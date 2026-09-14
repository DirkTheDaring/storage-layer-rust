//! Runs the SAME shared backend contract suite (storage-core `contract`
//! module) against the REAL S3 adapter over the honest mock client — the
//! central Phase 2 conformance deliverable. Executed twice: rooted at the
//! bucket root, and rooted under a configured physical prefix (the full
//! contract must be prefix-invariant, proving physical-prefix isolation at
//! the semantic level).

mod common;

use std::sync::Arc;

use common::MockS3Client;
use storage_core::contract;
use storage_s3::S3ObjectStore;

fn fresh_store(prefix: Option<&str>) -> S3ObjectStore {
    S3ObjectStore::new(Arc::new(MockS3Client::new()), prefix).expect("construct store")
}

#[tokio::test(flavor = "multi_thread")]
async fn real_s3_adapter_satisfies_core_contract_suite() {
    let store = fresh_store(None);
    contract::run_core_suite(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn real_s3_adapter_satisfies_core_contract_suite_under_physical_prefix() {
    let store = fresh_store(Some("tenant-a/objects"));
    contract::run_core_suite(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn real_s3_adapter_individual_checks_on_fresh_stores() {
    contract::check_write_then_read(&fresh_store(None)).await;
    contract::check_write_if_absent(&fresh_store(None)).await;
    contract::check_version_observation(&fresh_store(None)).await;
    contract::check_replace_if_version(&fresh_store(None)).await;
    contract::check_delete_idempotent(&fresh_store(None)).await;
    contract::check_delete_if_version(&fresh_store(None)).await;
    contract::check_listing(&fresh_store(None)).await;
    contract::check_read_bound(&fresh_store(None)).await;
    contract::check_dot_prefixed_keys_are_ordinary_objects(&fresh_store(None)).await;
    contract::check_invalid_key_rejection();
}
