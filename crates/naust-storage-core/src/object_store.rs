//! Backend-neutral object-store contracts (STORAGE-LAYER-MIGRATION Phase 0).
//!
//! One semantic surface that filesystem and S3 adapters implement so the
//! registry layer can compose its objects exactly once. Contracts here are
//! registry-domain-free and backend-domain-free: no manifest/tag/membership
//! vocabulary, no ETag/errno/inode/SDK types, no continuation-token encodings.
//!
//! # Normative boundaries
//! - **Absence is an outcome, not an error.** Reads return `Option`;
//!   conditional mutations return outcome enums; unconditional [`delete`]
//!   returns unit (success means the key is absent, with no claim about
//!   prior existence). [`StoreError`] is reserved for genuine failures,
//!   which every operation reports truthfully — there is deliberately no
//!   "best effort" write or delete at this layer. Ignoring a failure is a
//!   caller policy applied ABOVE this boundary.
//! - **Single-object semantics only.** No multi-object transaction, no
//!   snapshot listing, no compare-and-rename is promised anywhere.
//! - **Version tokens are opaque.** See [`ObjectVersion`] / [`ListingVersion`].
//! - **Error mapping direction:** backend-native failures (errno, SDK errors)
//!   map INTO [`StoreError`] inside an adapter, surviving only as diagnostic
//!   `source`/message text; registry code maps [`StoreError`] into its domain
//!   errors and must never need to inspect backend-native details.

use std::num::NonZeroUsize;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;

use crate::key::ObjectKey;

/// Opaque token associated with ONE observed generation of ONE object,
/// issued/derived by the store that produced the observation and suitable
/// for a LATER conditional mutation on the same store and key according to
/// that store's precondition semantics.
///
/// # Guarantee (operational, not representational)
/// If the supplied version is stale under the backend's supported
/// conditional-mutation mechanism — the observed generation is no longer the
/// current one — then [`ObjectStore::replace_if_version`] and
/// [`ObjectStore::delete_if_version`] MUST NOT mutate the protected current
/// generation.
///
/// # Explicitly NOT guaranteed
/// - NOT a content digest or collision-free content identity (registry
///   content identity belongs to registry digests, above this boundary);
/// - NOT globally unique, NOT portable between stores or backends;
/// - NOT lexically ordered, NOT a generation counter;
/// - NOT meaningful to callers: registry code owns, clones, compares for
///   equality, and round-trips tokens — never parses or branches on their
///   representation (see [`adapter`] for the only construction/inspection
///   surface, which is out of contract for registry logic).
///
/// A backend whose mechanism cannot distinguish identical-byte rewrites may
/// issue a fresh token for them; callers may treat a precondition mismatch
/// only as "the observed generation is gone", never as a payload-equality
/// statement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectVersion(String);

/// Opaque WEAK observation token attached to listing rows.
///
/// # What it represents
/// A per-row observation made during enumeration WITHOUT opening the object
/// (metadata-granularity on filesystems; whatever the service reports on
/// remote stores).
///
/// # What it may be used for
/// Caller-side change heuristics and strategy-level guards that re-observe
/// before acting (the accepted GC candidate flow: a listing-grade candidate
/// token guards the mark stage; the final conditional deletion re-observes
/// to obtain an object-grade token or delegates revalidation to the
/// backend's conditional mechanism).
///
/// # What it MUST NOT be used for
/// It is NOT an [`ObjectVersion`] and is never accepted by
/// `replace_if_version`/`delete_if_version` — the type system enforces this;
/// no conversion between the two exists in this crate, deliberately. An
/// adapter whose listing observation happens to be read-grade may offer a
/// documented adapter-SPECIFIC bridge, but generic callers cannot assume
/// one. A caller that needs an object-grade token performs a re-observation
/// (`read_with_version`). This preserves the accepted two-stage GC token
/// contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListingVersion(String);

/// Opaque strictly-after continuation token for [`ObjectStore::list_page`].
///
/// The caller contract is deliberately minimal: clone it and round-trip it
/// unchanged into a later `list_page` on the same store and prefix. Equality
/// comparison and serialization are NOT part of the contract (wire-level
/// pagination remains a registry-domain concern composed from row data, as
/// today); offering serialization would freeze backend cursor models and is
/// deliberately withheld. A token fed to a different store/prefix may yield
/// [`StoreError::InvalidInput`].
#[derive(Clone, Debug)]
pub struct PageToken(String);

/// Adapter-support surface: the ONLY construction/inspection point for the
/// opaque token types.
///
/// Rust has no "friend crate" visibility, so these functions are necessarily
/// `pub` for the separate backend adapter crates (the filesystem adapter,
/// the future S3 adapter) and for contract-suite scaffolding. They are OUT
/// OF CONTRACT for registry domain logic: registry code MUST NOT call this
/// module or otherwise depend on token representations. That boundary is
/// enforced by review convention (and greppable imports), not by the
/// compiler — stated here explicitly rather than pretending `pub` is
/// private. Keeping construction OFF the token types themselves keeps the
/// tempting surface out of the types' API entirely.
pub mod adapter {
    use super::{ListingVersion, ObjectVersion, PageToken};

    pub fn object_version(token: impl Into<String>) -> ObjectVersion {
        ObjectVersion(token.into())
    }

    pub fn object_version_token(version: &ObjectVersion) -> &str {
        &version.0
    }

    pub fn listing_version(token: impl Into<String>) -> ListingVersion {
        ListingVersion(token.into())
    }

    pub fn listing_version_token(version: &ListingVersion) -> &str {
        &version.0
    }

    pub fn page_token(token: impl Into<String>) -> PageToken {
        PageToken(token.into())
    }

    pub fn page_token_value(token: &PageToken) -> &str {
        &token.0
    }
}

/// Metadata observed for one stored object generation.
///
/// This is the object-store evolution of the read-side `ObjectMetadata`
/// (whose docs defer version/timestamp fields); the two converge when the
/// read seams migrate onto this module. `modified` is `None` where the
/// backend genuinely has no modification timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectMeta {
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// A buffered read of one committed object generation.
#[derive(Clone, Debug)]
pub struct ObjectRead {
    pub meta: ObjectMeta,
    pub bytes: Bytes,
}

/// A buffered read carrying the generation's [`ObjectVersion`].
#[derive(Clone, Debug)]
pub struct VersionedRead {
    pub meta: ObjectMeta,
    pub version: ObjectVersion,
    pub bytes: Bytes,
}

/// Persistence strength for successful writes. Named by the guarantee the
/// caller receives, never by caller intent: writes of BOTH strengths report
/// failures truthfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Atomic full-object replacement that, before returning success, has
    /// completed the backend's accepted durable-publication sequence (for a
    /// filesystem: payload sync + atomic rename + directory-entry
    /// persistence; for a remote object service: acknowledged write under the
    /// service's durability model). Authoritative registry state uses this.
    Durable,
    /// Atomic full-object replacement that is immediately VISIBLE to
    /// subsequent reads of this store, but whose crash-persistence is only
    /// whatever the backend provides by default; a crash may legitimately
    /// lose it. Intended solely for reconstructible/cache state. Errors are
    /// still reported truthfully.
    Visible,
}

/// Outcome of [`ObjectStore::write_if_absent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    /// No object existed; this call atomically created the new generation.
    Created(ObjectVersion),
    /// An object already exists. Nothing was mutated. `current` carries the
    /// existing generation's version where the backend can report it cheaply.
    AlreadyExists { current: Option<ObjectVersion> },
}

/// Outcome of [`ObjectStore::replace_if_version`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// The observed generation was current; the object now holds the new
    /// generation whose version is returned.
    Replaced(ObjectVersion),
    /// The object exists but is no longer the observed generation. Nothing
    /// was mutated; the current object is preserved byte-for-byte.
    PreconditionFailed { current: Option<ObjectVersion> },
    /// No object exists at the key. Nothing was created: a conditional
    /// replace never resurrects a deleted object.
    Absent,
}

/// Outcome of [`ObjectStore::delete_if_version`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionalDeleteOutcome {
    /// The observed generation was current and has been removed.
    Deleted,
    /// No object exists at the key. Nothing was mutated.
    Absent,
    /// The object exists but is no longer the observed generation — for
    /// example it was replaced after the observation. The CURRENT object is
    /// preserved: a stale observation can never delete a replacement.
    PreconditionFailed { current: Option<ObjectVersion> },
}

/// One row of a listing page. `key` is the row's full [`ObjectKey`]; `leaf`
/// is its final component relative to the listed prefix (single component —
/// structurally nested backend entries are excluded by the adapter). The
/// storage layer reports STORAGE objects only: whether a row is a valid
/// registry object (name grammar, payload decode, corruption policy) is
/// decided by the registry exactly once, above this boundary.
#[derive(Clone, Debug)]
pub struct ListedObject {
    pub key: ObjectKey,
    pub leaf: String,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub version: ListingVersion,
}

/// One page of listing results. `next` is present iff more rows exist
/// strictly after the last returned row.
#[derive(Clone, Debug)]
pub struct ListPage {
    pub objects: Vec<ListedObject>,
    pub next: Option<PageToken>,
}

/// Failures of object-store operations. Deliberately minimal: absence,
/// existence conflicts, and precondition mismatches are OUTCOMES, not errors.
///
/// Backend-native details (errno values, SDK error types, HTTP statuses)
/// appear only as `source`/message diagnostics; no caller may need to
/// inspect them to behave correctly.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Structurally invalid input: a foreign/undecodable continuation token,
    /// an out-of-range argument. Never used for absent objects.
    #[error("invalid input: {message}")]
    InvalidInput { message: String },

    /// The object exceeds the caller-supplied byte ceiling. Nothing was
    /// truncated: bounded reads either return complete payloads or fail.
    #[error("object exceeds read limit of {limit} bytes")]
    TooLarge { limit: u64 },

    /// The backend denied access. Includes containment refusals a filesystem
    /// adapter reports for escape attempts it fails closed on.
    #[error("permission denied: {message}")]
    PermissionDenied {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The backend's OWN storage shape is invalid (impossible enumeration
    /// results, undecodable backend-native listing state). NOT for registry
    /// payload corruption, which is judged above this boundary.
    #[error("corrupt storage state: {message}")]
    Corrupt { message: String },

    /// Transport/service/OS failure. The operation may or may not have taken
    /// effect; callers retry or surface per their own policy.
    #[error("backend failure: {message}")]
    Backend {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl StoreError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::PermissionDenied {
            message: message.into(),
            source: None,
        }
    }

    pub fn corrupt(message: impl Into<String>) -> Self {
        Self::Corrupt {
            message: message.into(),
        }
    }

    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
            source: None,
        }
    }
}

/// Backend-neutral object store: the Phase 0 minimal semantic core.
///
/// Implementations exist per backend (filesystem adapter over pinned-root
/// contained primitives; S3 adapter over conditional object operations) and
/// MUST satisfy the shared contract suite (`contract` module) — the
/// signatures alone are not the contract.
///
/// # Concurrency envelope
/// Each method guarantees exactly its documented single-object semantics.
/// Cross-operation serialization (mutual exclusion of GC and mutations,
/// cross-process exclusivity) remains the caller's coordination layer, as
/// established by the accepted campaign.
///
/// # Streaming boundary
/// This trait's reads are BOUNDED buffered reads for metadata-sized
/// authoritative objects (callers supply the ceiling; adapters must not
/// buffer beyond it). Large-payload streaming reads remain on the existing
/// `ObjectPayloadReader` contract; streaming/appending writes are future
/// capability traits, deliberately not part of the Phase 0 core.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Observes existence and metadata. `None` iff absent at observation
    /// time. Never mutates.
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, StoreError>;

    /// Reads the complete payload of one committed generation, or `None` if
    /// absent. Fails with [`StoreError::TooLarge`] (reading nothing usable)
    /// if the payload exceeds `max_len`; never truncates.
    async fn read(&self, key: &ObjectKey, max_len: u64) -> Result<Option<ObjectRead>, StoreError>;

    /// As [`read`](Self::read), additionally returning the generation's
    /// [`ObjectVersion`] for later conditional mutation.
    async fn read_with_version(
        &self,
        key: &ObjectKey,
        max_len: u64,
    ) -> Result<Option<VersionedRead>, StoreError>;

    /// Atomic full-object create-or-replace. Concurrent readers observe the
    /// prior generation or the new one, never a mixture. Success at
    /// [`Durability::Durable`] additionally means the backend's accepted
    /// durable-publication sequence completed. Missing intermediate
    /// namespace structure is the adapter's concern.
    async fn write(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ObjectVersion, StoreError>;

    /// Atomic create-if-absent: within the caller's supported coordination
    /// envelope at most one concurrent creator succeeds; losers observe
    /// [`CreateOutcome::AlreadyExists`] and the existing object is preserved.
    async fn write_if_absent(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<CreateOutcome, StoreError>;

    /// Conditional replace: mutates iff the current generation is `expected`;
    /// otherwise preserves the current object byte-for-byte and reports the
    /// outcome. Never creates on absence.
    async fn replace_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ReplaceOutcome, StoreError>;

    /// Idempotent unconditional removal: success means the backend
    /// accepted/completed the operation required to make the key ABSENT
    /// under its supported semantics — an already-absent key is equally
    /// success. Deliberately NO claim is made about whether an object
    /// previously existed: no portable backend mechanism provides that
    /// distinction atomically (a filesystem unlink can; an idempotent remote
    /// DeleteObject cannot, and a HEAD-then-DELETE emulation would be racy —
    /// this contract refuses to hide that race). Callers that need
    /// "remove the generation I observed" use
    /// [`read_with_version`](Self::read_with_version) +
    /// [`delete_if_version`](Self::delete_if_version) instead.
    ///
    /// All backend failures surface as errors — there is no best-effort
    /// delete at this layer; ignoring a failure is caller policy above it.
    /// Crash-persistence of removals follows the backend's accepted
    /// deletion-durability policy; success guarantees the immediate
    /// namespace mutation.
    async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError>;

    /// Conditional removal: removes iff the current generation is `expected`.
    /// A stale observation preserves the current (replacement) object.
    async fn delete_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError>;

    /// Lists one page of stored objects.
    ///
    /// # Contract
    /// - Rows are the DIRECT children of `prefix` (`None` = store root) that
    ///   are objects; structurally nested or non-object backend entries are
    ///   excluded by the adapter. Registry validity/corruption policy is NOT
    ///   applied here.
    /// - Ordering: ascending byte-lexical by `leaf`, stable across pages.
    /// - `after`: strictly-after continuation — the page starts at the first
    ///   leaf greater than the token's position; a token from a different
    ///   store/prefix may fail with [`StoreError::InvalidInput`].
    /// - Exactly-once: no duplicate leaf within a page or across a
    ///   token-continued walk of an unchanged namespace.
    /// - Absent prefix ⇒ empty page with no token. Callers never observe an
    ///   empty page WITH a token.
    /// - Concurrent mutations: rows are live observations; a listed object
    ///   may be gone by follow-up read (callers treat as benign absence) and
    ///   concurrently inserted leaves before the cursor may be missed. No
    ///   snapshot is promised.
    /// - Backend enumeration failures and undecodable backend-native state
    ///   surface as errors; adapters never silently skip failures.
    async fn list_page(
        &self,
        prefix: Option<&ObjectKey>,
        after: Option<&PageToken>,
        limit: NonZeroUsize,
    ) -> Result<ListPage, StoreError>;
}
