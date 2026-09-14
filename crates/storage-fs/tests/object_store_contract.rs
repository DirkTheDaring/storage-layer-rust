//! Runs the shared backend contract suite (storage-core `contract` module)
//! against the REAL filesystem adapter over isolated temporary roots — the
//! central Phase 1 conformance deliverable. The suite is not duplicated:
//! these are the exact checks the reference model passes.

use storage_core::contract;
use storage_fs::FsObjectStore;
use tempfile::TempDir;

fn fresh_store() -> (TempDir, FsObjectStore) {
    let dir = TempDir::new().expect("tempdir");
    let store = FsObjectStore::open(dir.path()).expect("open fs object store");
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn real_fs_adapter_satisfies_core_contract_suite() {
    let (_root, store) = fresh_store();
    contract::run_core_suite(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn real_fs_adapter_individual_checks_on_fresh_stores() {
    {
        let (_r, s) = fresh_store();
        contract::check_write_then_read(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_write_if_absent(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_version_observation(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_replace_if_version(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_delete_idempotent(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_delete_if_version(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_listing(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_read_bound(&s).await;
    }
    {
        let (_r, s) = fresh_store();
        contract::check_dot_prefixed_keys_are_ordinary_objects(&s).await;
    }
    contract::check_invalid_key_rejection();
}
