//! Deterministic mock [`S3Client`] for tests (feature `mock-client`).
//!
//! Models S3 semantics honestly: quoted multipart-style ETags that change
//! on every write, ATOMIC conditional evaluation (one mutex guards the
//! check-and-apply of `If-Match`/`If-None-Match`, as the service does),
//! delimiter listing with byte-lexical order, `start_after`, server-side
//! page caps and truncation, byte-bound enforcement while "streaming", and
//! injectable per-operation failures. It exercises the real adapter logic:
//! request shapes, classification, pagination, token handling.
//!
//! Exported behind the `mock-client` feature so downstream crates (and this
//! crate's own integration tests) can drive `S3ObjectStore` deterministically
//! without an S3 endpoint. Test support only — never a production surface.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;

use crate::client::{
    GetResult, ObjectStat, PutPrecondition, RawConditionalDelete, RawListPage, S3ApiError,
    S3Client, too_large_sentinel,
};

type Hook = Box<dyn Fn(&str, &str) -> Option<(u16, &'static str, &'static str)> + Send + Sync>;

#[derive(Clone)]
struct Stored {
    bytes: Bytes,
    etag: String,
    modified: SystemTime,
}

#[derive(Default)]
pub struct MockS3Client {
    objects: Mutex<BTreeMap<String, Stored>>,
    etag_seq: AtomicU64,
    /// (op, key) -> optional injected (status, code, message).
    hook: Mutex<Option<Hook>>,
    /// Server-side listing page cap (forces multi-round-trip pagination).
    pub list_server_max: Mutex<usize>,
    /// Number of times `list_direct_children` should return an EMPTY page
    /// flagged truncated (models a misbehaving backend for the
    /// no-forward-progress guard).
    pub force_empty_truncated: Mutex<usize>,
}

impl MockS3Client {
    pub fn new() -> Self {
        Self {
            list_server_max: Mutex::new(1000),
            ..Default::default()
        }
    }

    pub fn raw_insert_string_key(&self, key: String, bytes: &'static [u8]) {
        let etag = self.next_etag();
        self.objects.lock().unwrap().insert(
            key,
            Stored {
                bytes: Bytes::from_static(bytes),
                etag,
                modified: SystemTime::now(),
            },
        );
    }

    pub fn set_hook<F>(&self, f: F)
    where
        F: Fn(&str, &str) -> Option<(u16, &'static str, &'static str)> + Send + Sync + 'static,
    {
        *self.hook.lock().unwrap() = Some(Box::new(f));
    }

    pub fn clear_hook(&self) {
        *self.hook.lock().unwrap() = None;
    }

    pub fn object_count(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    pub fn raw_insert(&self, key: &str, bytes: &'static [u8]) {
        let etag = self.next_etag();
        self.objects.lock().unwrap().insert(
            key.to_string(),
            Stored {
                bytes: Bytes::from_static(bytes),
                etag,
                modified: SystemTime::now(),
            },
        );
    }

    /// Owned-bytes variant of [`Self::raw_insert`] for callers seeding
    /// dynamically composed payloads.
    pub fn raw_insert_bytes(&self, key: &str, bytes: Vec<u8>) {
        let etag = self.next_etag();
        self.objects.lock().unwrap().insert(
            key.to_string(),
            Stored {
                bytes: Bytes::from(bytes),
                etag,
                modified: SystemTime::now(),
            },
        );
    }

    pub fn raw_bytes(&self, key: &str) -> Option<Bytes> {
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .map(|s| s.bytes.clone())
    }

    /// Quoted, multipart-looking ETags — deliberately NOT hex/MD5-shaped.
    fn next_etag(&self) -> String {
        let n = self.etag_seq.fetch_add(1, Ordering::Relaxed);
        format!("\"mock-{n}-3\"")
    }

    fn fire(&self, op: &str, key: &str) -> Result<(), S3ApiError> {
        if let Some(hook) = self.hook.lock().unwrap().as_ref()
            && let Some((status, code, msg)) = hook(op, key)
        {
            return Err(S3ApiError::new(Some(status), Some(code), msg));
        }
        Ok(())
    }
}

fn norm(e: &str) -> String {
    e.trim_matches('"').to_string()
}

#[async_trait]
impl S3Client for MockS3Client {
    async fn head_object(&self, key: &str) -> Result<Option<ObjectStat>, S3ApiError> {
        self.fire("head", key)?;
        Ok(self.objects.lock().unwrap().get(key).map(|s| ObjectStat {
            size: s.bytes.len() as u64,
            modified: Some(s.modified),
            etag: s.etag.clone(),
        }))
    }

    async fn get_object(&self, key: &str, max_len: u64) -> Result<Option<GetResult>, S3ApiError> {
        self.fire("get", key)?;
        let objs = self.objects.lock().unwrap();
        let Some(s) = objs.get(key) else {
            return Ok(None);
        };
        if s.bytes.len() as u64 > max_len {
            return Err(S3ApiError::new(
                None,
                Some(&too_large_sentinel(max_len)),
                "object exceeds caller byte bound",
            ));
        }
        Ok(Some(GetResult {
            stat: ObjectStat {
                size: s.bytes.len() as u64,
                modified: Some(s.modified),
                etag: s.etag.clone(),
            },
            bytes: s.bytes.clone(),
        }))
    }

    async fn put_object(
        &self,
        key: &str,
        bytes: Bytes,
        precondition: PutPrecondition,
    ) -> Result<String, S3ApiError> {
        self.fire("put", key)?;
        // ONE lock across evaluate + apply: service-atomic conditionals.
        let mut objs = self.objects.lock().unwrap();
        match &precondition {
            PutPrecondition::None => {}
            PutPrecondition::IfNoneMatchAny => {
                if objs.contains_key(key) {
                    return Err(S3ApiError::new(
                        Some(412),
                        Some("PreconditionFailed"),
                        "If-None-Match: * failed: object exists",
                    ));
                }
            }
            PutPrecondition::IfMatch(expected) => match objs.get(key) {
                None => {
                    return Err(S3ApiError::new(
                        Some(404),
                        Some("NoSuchKey"),
                        "If-Match on absent object",
                    ));
                }
                Some(cur) if norm(&cur.etag) != norm(expected) => {
                    return Err(S3ApiError::new(
                        Some(412),
                        Some("PreconditionFailed"),
                        "If-Match failed: stale etag",
                    ));
                }
                Some(_) => {}
            },
        }
        let etag = self.next_etag();
        objs.insert(
            key.to_string(),
            Stored {
                bytes,
                etag: etag.clone(),
                modified: SystemTime::now(),
            },
        );
        Ok(etag)
    }

    async fn delete_object(&self, key: &str) -> Result<(), S3ApiError> {
        self.fire("delete", key)?;
        // Native S3: deleting an absent key is 204 success.
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn delete_object_if_match(
        &self,
        key: &str,
        etag: &str,
    ) -> Result<RawConditionalDelete, S3ApiError> {
        self.fire("delete_if_match", key)?;
        let mut objs = self.objects.lock().unwrap();
        match objs.get(key) {
            None => Ok(RawConditionalDelete::NotFound),
            Some(cur) if norm(&cur.etag) != norm(etag) => {
                Ok(RawConditionalDelete::PreconditionFailed)
            }
            Some(_) => {
                objs.remove(key);
                Ok(RawConditionalDelete::Deleted)
            }
        }
    }

    async fn list_direct_children(
        &self,
        dir_prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<RawListPage, S3ApiError> {
        self.fire("list", dir_prefix)?;
        {
            let mut forced = self.force_empty_truncated.lock().unwrap();
            if *forced > 0 {
                *forced -= 1;
                return Ok(RawListPage {
                    objects: Vec::new(),
                    truncated: true,
                });
            }
        }
        let cap = (*self.list_server_max.lock().unwrap()).min(max_keys).max(1);
        let objs = self.objects.lock().unwrap();
        let mut out = Vec::new();
        let mut truncated = false;
        for (key, s) in objs.iter() {
            let Some(rest) = key.strip_prefix(dir_prefix) else {
                continue;
            };
            if let Some(sa) = start_after
                && key.as_str() <= sa
            {
                continue;
            }
            // Delimiter mode: nested keys become common prefixes, not rows.
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            if out.len() == cap {
                truncated = true;
                break;
            }
            out.push((
                key.clone(),
                ObjectStat {
                    size: s.bytes.len() as u64,
                    modified: Some(s.modified),
                    etag: s.etag.clone(),
                },
            ));
        }
        Ok(RawListPage {
            objects: out,
            truncated,
        })
    }
}
