//! Bounded per-stream reconstruction state for normalized envelope deliveries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use thiserror::Error as ThisError;

use crate::{
    fingerprint::{self, SemanticFingerprint},
    ir::{
        Baseline, CacheGroup, EventEnvelope, Mutation, OpaqueHash, Origin, Record, StorageMedium,
        StreamDeclaration, ValidatedRecord, ValidationError,
    },
    limits::{Limits, MAX_JSON_DEPTH},
};

/// External trust decision applied to a trace's baseline claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaselineAuthority {
    /// A pinned adapter or synthetic fixture established the declared empty baseline.
    TrustDeclaredEmpty,
    /// Treat the initial cache membership as unknown, regardless of the raw claim.
    TreatAsUnknown,
}

/// Whether the modeled cache view is authoritative at its current frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Certainty {
    /// The view follows a trusted anchor with no unresolved delivery gap.
    Exact,
    /// The view is authoritative only through its frontier and awaits a gap.
    Recovering,
    /// The trace cannot establish an authoritative complete view.
    Unknown,
}

/// Content-free reasons that make a finalized view ineligible for exactness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnknownReasons(u8);

impl UnknownReasons {
    const BASELINE: u8 = 1 << 0;
    const EQUIVOCATION: u8 = 1 << 1;
    const UNAVAILABLE_GAP: u8 = 1 << 2;
    const UNCLOSED_GAP: u8 = 1 << 3;

    const fn active(baseline: bool, equivocation: bool, unavailable_gap: bool) -> Self {
        Self(
            (if baseline { Self::BASELINE } else { 0 })
                | (if equivocation { Self::EQUIVOCATION } else { 0 })
                | (if unavailable_gap {
                    Self::UNAVAILABLE_GAP
                } else {
                    0
                }),
        )
    }

    const fn with_unclosed_gap(mut self, unclosed_gap: bool) -> Self {
        if unclosed_gap {
            self.0 |= Self::UNCLOSED_GAP;
        }
        self
    }

    /// The stream began without an externally trusted empty baseline or barrier.
    #[must_use]
    pub const fn baseline(self) -> bool {
        self.0 & Self::BASELINE != 0
    }

    /// A relevant applied or pending cursor carried conflicting payloads.
    #[must_use]
    pub const fn equivocation(self) -> bool {
        self.0 & Self::EQUIVOCATION != 0
    }

    /// Gap evidence was discarded at a configured modeled-state ceiling.
    #[must_use]
    pub const fn unavailable_gap(self) -> bool {
        self.0 & Self::UNAVAILABLE_GAP != 0
    }

    /// Finalization reached EOF with retained out-of-order evidence.
    #[must_use]
    pub const fn unclosed_gap(self) -> bool {
        self.0 & Self::UNCLOSED_GAP != 0
    }

    /// Whether no active unknown reason remains.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Content-free result of admitting one physical delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Disposition {
    /// The delivery and any newly contiguous pending suffix were folded.
    Applied,
    /// A forward clear established a new authoritative membership anchor.
    BarrierApplied,
    /// The delivery was retained behind a gap.
    Buffered,
    /// The same retained cursor and semantic payload was seen again.
    Duplicate,
    /// The same retained cursor carried a different semantic payload.
    Equivocation,
    /// The cursor was behind the frontier but outside fingerprint coverage.
    StaleUnverifiable,
    /// A stale clear could not be used as a forward membership barrier.
    StaleBarrier,
    /// Pending count or retained-byte capacity rejected the delivery.
    PendingLimit,
    /// The cursor was farther ahead than the configured modeled gap span.
    GapLimit,
    /// Earlier discarded evidence makes this cursor impossible to verify.
    UnverifiableGap,
}

/// Bounded resource exhausted during source normalization or cache folding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Resource {
    /// Canonical mutation bytes for one physical envelope.
    CanonicalMutationBytes,
    /// Canonical mutation bytes hashed across the physical source trace.
    FingerprintBytes,
    /// Canonical stream declarations registered in one normalization session.
    SessionStreams,
    /// Physical source envelopes normalized in one session.
    SessionEnvelopes,
    /// Stream-identity and envelope-ID bytes retained by one session.
    SessionIdentityBytes,
    /// Canonical cache keys retained for one stream.
    CacheKeys,
    /// Variable identity bytes retained by one stream's cache view.
    CacheIdentityBytes,
}

impl fmt::Display for Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CanonicalMutationBytes => "canonical_mutation_bytes",
            Self::FingerprintBytes => "fingerprint_bytes",
            Self::SessionStreams => "session_streams",
            Self::SessionEnvelopes => "session_envelopes",
            Self::SessionIdentityBytes => "session_identity_bytes",
            Self::CacheKeys => "cache_keys",
            Self::CacheIdentityBytes => "cache_identity_bytes",
        })
    }
}

/// Stable state-layer failures that never echo trace-controlled identities.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Configured recursion exceeds the library's stack-safety ceiling.
    #[error("configured JSON depth {configured} exceeds hard maximum {maximum}")]
    UnsupportedDepthLimit {
        /// Requested maximum JSON depth.
        configured: usize,
        /// Compile-time stack-safety ceiling.
        maximum: usize,
    },
    /// A normalizer was used after its first failure.
    #[error("envelope normalizer is already failed")]
    NormalizerFailed,
    /// A stream state was used after its first hard failure.
    #[error("stream state is already failed")]
    StateFailed,
    /// A prepared envelope came from a different normalization session.
    #[error("prepared envelope belongs to a different trace session")]
    SessionMismatch,
    /// A stream ID was registered with conflicting immutable stream facts.
    #[error("stream ID conflicts with its registered stream contract")]
    ConflictingStreamRegistration,
    /// One canonical publisher identity was registered under two stream IDs.
    #[error("canonical stream identity is already registered")]
    DuplicateStreamScope,
    /// A physical envelope ID was registered more than once.
    #[error("envelope ID is already registered in this session")]
    DuplicateEnvelopeRegistration,
    /// The API received a different top-level record kind than required.
    #[error("record kind is not valid for this state operation")]
    WrongRecordKind,
    /// A record accepted under looser ceilings failed the active ceilings.
    #[error("record failed active state limits: {error}")]
    RecordValidation {
        /// Redacted record-local failure.
        error: ValidationError,
    },
    /// The canonical serializer unexpectedly rejected typed mutations.
    #[error("semantic fingerprint canonicalization failed")]
    FingerprintCanonicalization,
    /// A hard normalization or cache-view ceiling was exceeded.
    #[error("state {resource} limit {maximum} exceeded by observed value {observed}")]
    ResourceLimit {
        /// Resource whose budget was exhausted.
        resource: Resource,
        /// Configured inclusive maximum.
        maximum: u64,
        /// First value known to exceed that maximum.
        observed: u64,
    },
    /// Checked state accounting could not be represented.
    #[error("state counter overflow")]
    CounterOverflow,
    /// Trusted-empty authority was applied to a non-empty baseline declaration.
    #[error("trusted-empty authority does not match the stream baseline")]
    BaselineAuthorityMismatch,
    /// A delivery belongs to a different publisher stream.
    #[error("delivery does not belong to this stream state")]
    StreamMismatch,
    /// A delivery cursor was below the stream's first valid cursor.
    #[error("delivery cursor is below the stream initial cursor")]
    CursorBeforeInitial,
}

impl Error {
    /// Return a machine-stable error code without trace-derived text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedDepthLimit { .. } => "unsupported_depth_limit",
            Self::NormalizerFailed => "normalizer_failed",
            Self::StateFailed => "state_failed",
            Self::SessionMismatch => "session_mismatch",
            Self::ConflictingStreamRegistration => "conflicting_stream_registration",
            Self::DuplicateStreamScope => "duplicate_stream_scope",
            Self::DuplicateEnvelopeRegistration => "duplicate_envelope_registration",
            Self::WrongRecordKind => "wrong_record_kind",
            Self::RecordValidation { .. } => "record_validation",
            Self::FingerprintCanonicalization => "fingerprint_canonicalization",
            Self::ResourceLimit { .. } => "state_resource_limit",
            Self::CounterOverflow => "counter_overflow",
            Self::BaselineAuthorityMismatch => "baseline_authority_mismatch",
            Self::StreamMismatch => "stream_mismatch",
            Self::CursorBeforeInitial => "cursor_before_initial",
        }
    }
}

/// One immutable source envelope normalized and fingerprinted exactly once.
///
/// The type intentionally exposes neither its semantic digest nor serialization.
pub struct PreparedEnvelope {
    session: Arc<SessionMarker>,
    envelope_id: Arc<str>,
    stream_id: Box<str>,
    cursor: u64,
    origin: Origin,
    mutations: Box<[Mutation]>,
    fingerprint: SemanticFingerprint,
    canonical_bytes: u64,
    first_clear: Option<usize>,
}

impl PreparedEnvelope {
    /// Stable trace-local identity retained for schedules and witnesses.
    #[must_use]
    pub fn envelope_id(&self) -> &str {
        self.envelope_id.as_ref()
    }

    /// Observed live or replay provenance, excluded from semantic equality.
    #[must_use]
    pub const fn origin(&self) -> Origin {
        self.origin
    }

    fn cursor(&self) -> u64 {
        self.cursor
    }

    fn has_clear(&self) -> bool {
        self.first_clear.is_some()
    }
}

/// Fail-closed normalizer with a cumulative canonical hashing budget.
pub struct EnvelopeNormalizer {
    session: Arc<SessionMarker>,
    limits: Limits,
    fingerprint_bytes: u64,
    streams: BTreeMap<Arc<str>, Arc<RegisteredStream>>,
    scopes: BTreeMap<Arc<CacheScope>, Arc<str>>,
    envelope_ids: BTreeSet<Arc<str>>,
    envelopes: u64,
    identity_bytes: u64,
}

struct SessionMarker {
    status: AtomicU8,
}

const SESSION_OPEN: u8 = 0;
const SESSION_SEALED: u8 = 1;
const SESSION_FAILED: u8 = 2;

/// Opaque proof that one normalization session reached EOF without failure.
pub struct SealedSession {
    session: Arc<SessionMarker>,
}

/// Immutable, session-bound recipe for fresh states of one declared stream.
///
/// A blueprint freezes the external baseline-authority decision during source
/// ingestion but retains no cache membership. It can therefore create pristine
/// and faulted states sequentially after the complete source session is sealed.
#[derive(Clone)]
pub struct StreamBlueprint {
    session: Arc<SessionMarker>,
    limits: Limits,
    registration: Arc<RegisteredStream>,
}

impl StreamBlueprint {
    /// Create a fresh empty consumer state after the source session reaches EOF.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SessionMismatch`] when the seal belongs to another
    /// source session, or [`Error::NormalizerFailed`] unless the matching
    /// session sealed successfully.
    pub fn start(&self, sealed: &SealedSession) -> Result<StreamState, Error> {
        if !Arc::ptr_eq(&self.session, &sealed.session) {
            return Err(Error::SessionMismatch);
        }
        if self.session.status.load(Ordering::Acquire) != SESSION_SEALED {
            return Err(Error::NormalizerFailed);
        }
        Ok(StreamState::from_blueprint(self))
    }
}

impl EnvelopeNormalizer {
    /// Create a source-envelope normalizer under explicit finite limits.
    ///
    /// # Errors
    ///
    /// Rejects a JSON depth above the compile-time stack-safety ceiling.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        validate_depth(&limits)?;
        Ok(Self {
            session: Arc::new(SessionMarker {
                status: AtomicU8::new(SESSION_OPEN),
            }),
            limits,
            fingerprint_bytes: 0,
            streams: BTreeMap::new(),
            scopes: BTreeMap::new(),
            envelope_ids: BTreeSet::new(),
            envelopes: 0,
            identity_bytes: 0,
        })
    }

    /// Consume and normalize one validated envelope record.
    ///
    /// The returned allocation can be shared by pristine, faulted, replay, and
    /// pending paths without recomputing its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a closed session, wrong record kind, active
    /// record limits, duplicate envelope ID, session envelope or identity
    /// budgets, canonicalization, cumulative hashing, or checked accounting.
    pub fn prepare(&mut self, record: ValidatedRecord) -> Result<Arc<PreparedEnvelope>, Error> {
        if self.session.status.load(Ordering::Acquire) != SESSION_OPEN {
            return Err(Error::NormalizerFailed);
        }
        let result = self.prepare_inner(record);
        if result.is_err() {
            self.fail();
        }
        result
    }

    /// Register one immutable stream contract and its external trust decision.
    ///
    /// Repeating an identical registration returns another lightweight handle
    /// to the same contract. The returned blueprint can create fresh states
    /// after this normalizer is consumed by [`Self::seal`].
    ///
    /// # Errors
    ///
    /// Returns a stable error for a closed session, unsupported active limits,
    /// a non-stream record, record validation, mismatched trusted-empty
    /// authority, conflicting registration, duplicate canonical scope, or
    /// session stream and identity budgets. A baseline-authority mismatch does
    /// not poison the session because no contract was registered.
    pub fn register_stream(
        &mut self,
        declaration: &ValidatedRecord,
        authority: BaselineAuthority,
    ) -> Result<StreamBlueprint, Error> {
        if self.session.status.load(Ordering::Acquire) != SESSION_OPEN {
            return Err(Error::NormalizerFailed);
        }
        validate_depth(&self.limits)?;
        if let Err(error) = declaration.as_record().validate(&self.limits) {
            self.fail();
            return Err(Error::RecordValidation { error });
        }
        let Record::Stream(stream) = declaration.as_record() else {
            self.fail();
            return Err(Error::WrongRecordKind);
        };
        if authority == BaselineAuthority::TrustDeclaredEmpty
            && stream.baseline != Baseline::EmptyAtEngineStart
        {
            return Err(Error::BaselineAuthorityMismatch);
        }
        let registration = self.bind_stream(stream, authority)?;
        Ok(StreamBlueprint {
            session: Arc::clone(&self.session),
            limits: self.limits,
            registration,
        })
    }

    /// Consume this session at EOF and make its stream states finalizable.
    ///
    /// Once sealed, no API handle remains that can normalize another physical
    /// envelope and invalidate the cumulative fingerprint budget.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NormalizerFailed`] if any earlier normalization or
    /// session-registration operation failed.
    pub fn seal(self) -> Result<SealedSession, Error> {
        if self
            .session
            .status
            .compare_exchange(
                SESSION_OPEN,
                SESSION_SEALED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(Error::NormalizerFailed);
        }
        Ok(SealedSession {
            session: Arc::clone(&self.session),
        })
    }

    /// Canonical mutation bytes successfully hashed so far.
    #[must_use]
    pub const fn fingerprint_bytes(&self) -> u64 {
        self.fingerprint_bytes
    }

    fn prepare_inner(&mut self, record: ValidatedRecord) -> Result<Arc<PreparedEnvelope>, Error> {
        record
            .as_record()
            .validate(&self.limits)
            .map_err(|error| Error::RecordValidation { error })?;
        let Record::Envelope(envelope) = record.as_record() else {
            return Err(Error::WrongRecordKind);
        };
        if self.envelope_ids.contains(envelope.envelope_id.as_str()) {
            return Err(Error::DuplicateEnvelopeRegistration);
        }
        let envelopes = self
            .envelopes
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        if envelopes > self.limits.max_envelopes_per_trace {
            return Err(Error::ResourceLimit {
                resource: Resource::SessionEnvelopes,
                maximum: self.limits.max_envelopes_per_trace,
                observed: envelopes,
            });
        }
        let identity_bytes = self
            .identity_bytes
            .checked_add(usize_to_u64(envelope.envelope_id.len())?)
            .ok_or(Error::CounterOverflow)?;
        if identity_bytes > self.limits.max_identity_bytes_per_trace {
            return Err(Error::ResourceLimit {
                resource: Resource::SessionIdentityBytes,
                maximum: self.limits.max_identity_bytes_per_trace,
                observed: identity_bytes,
            });
        }

        let remaining = self
            .limits
            .max_fingerprint_bytes_per_trace
            .checked_sub(self.fingerprint_bytes)
            .ok_or(Error::CounterOverflow)?;
        let remaining_usize = usize::try_from(remaining).unwrap_or(usize::MAX);
        let maximum = self.limits.max_line_bytes.min(remaining_usize);
        let limited_by_trace = remaining_usize < self.limits.max_line_bytes;
        let computed = fingerprint::envelope(envelope, maximum).map_err(|error| {
            map_fingerprint_error(error, limited_by_trace, self.fingerprint_bytes)
        })?;
        let canonical_bytes =
            u64::try_from(computed.canonical_bytes).map_err(|_| Error::CounterOverflow)?;
        let fingerprint_bytes = self
            .fingerprint_bytes
            .checked_add(canonical_bytes)
            .ok_or(Error::CounterOverflow)?;
        if fingerprint_bytes > self.limits.max_fingerprint_bytes_per_trace {
            return Err(Error::ResourceLimit {
                resource: Resource::FingerprintBytes,
                maximum: self.limits.max_fingerprint_bytes_per_trace,
                observed: fingerprint_bytes,
            });
        }

        let first_clear = envelope
            .mutations
            .iter()
            .position(|mutation| matches!(mutation, Mutation::Clear { .. }));
        let Record::Envelope(raw) = record.into_record() else {
            unreachable!("record kind was checked before ownership transfer");
        };
        let EventEnvelope {
            envelope_id,
            stream_id,
            cursor,
            origin,
            mutations,
            ..
        } = raw;
        let envelope_id: Arc<str> = Arc::from(envelope_id);
        self.fingerprint_bytes = fingerprint_bytes;
        self.envelopes = envelopes;
        self.identity_bytes = identity_bytes;
        let inserted = self.envelope_ids.insert(Arc::clone(&envelope_id));
        debug_assert!(inserted, "a prepared envelope ID must be newly registered");
        Ok(Arc::new(PreparedEnvelope {
            session: Arc::clone(&self.session),
            envelope_id,
            stream_id: stream_id.into_boxed_str(),
            cursor: cursor.get(),
            origin,
            mutations: mutations.into_boxed_slice(),
            fingerprint: computed.fingerprint,
            canonical_bytes,
            first_clear,
        }))
    }

    fn fail(&self) {
        self.session.status.store(SESSION_FAILED, Ordering::Release);
    }

    fn bind_stream(
        &mut self,
        stream: &StreamDeclaration,
        authority: BaselineAuthority,
    ) -> Result<Arc<RegisteredStream>, Error> {
        let result = self.bind_stream_inner(stream, authority);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn bind_stream_inner(
        &mut self,
        stream: &StreamDeclaration,
        authority: BaselineAuthority,
    ) -> Result<Arc<RegisteredStream>, Error> {
        let stream_id: Arc<str> = Arc::from(stream.stream_id.as_str());
        let scope = Arc::new(CacheScope::from(stream));
        let registration = RegisteredStream {
            stream_id: Arc::clone(&stream_id),
            scope: Arc::clone(&scope),
            initial_cursor: stream.initial_cursor.get(),
            baseline: stream.baseline,
            authority,
        };
        if let Some(registered) = self.streams.get(stream.stream_id.as_str()) {
            return if registered.as_ref() == &registration {
                Ok(Arc::clone(registered))
            } else {
                Err(Error::ConflictingStreamRegistration)
            };
        }
        if self.scopes.contains_key(scope.as_ref()) {
            return Err(Error::DuplicateStreamScope);
        }

        let observed_streams = usize_to_u64(self.streams.len())?
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        if observed_streams > self.limits.max_streams_per_trace {
            return Err(Error::ResourceLimit {
                resource: Resource::SessionStreams,
                maximum: self.limits.max_streams_per_trace,
                observed: observed_streams,
            });
        }
        let added_identity_bytes = usize_to_u64(stream.stream_id.len())?
            .checked_add(scope.identity_bytes()?)
            .ok_or(Error::CounterOverflow)?;
        let observed_identity_bytes = self
            .identity_bytes
            .checked_add(added_identity_bytes)
            .ok_or(Error::CounterOverflow)?;
        if observed_identity_bytes > self.limits.max_identity_bytes_per_trace {
            return Err(Error::ResourceLimit {
                resource: Resource::SessionIdentityBytes,
                maximum: self.limits.max_identity_bytes_per_trace,
                observed: observed_identity_bytes,
            });
        }

        let registration = Arc::new(registration);
        self.streams
            .insert(Arc::clone(&stream_id), Arc::clone(&registration));
        self.scopes.insert(scope, stream_id);
        self.identity_bytes = observed_identity_bytes;
        Ok(registration)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RegisteredStream {
    stream_id: Arc<str>,
    scope: Arc<CacheScope>,
    initial_cursor: u64,
    baseline: Baseline,
    authority: BaselineAuthority,
}

/// Canonical cache membership for one publisher stream.
///
/// Keys and hashes remain opaque; callers can compare snapshots and inspect
/// content-free resource counts, but cannot format trace-controlled values.
#[derive(Eq, PartialEq)]
pub struct CacheView {
    scope: Arc<CacheScope>,
    keys: BTreeSet<CacheKey>,
    identity_bytes: u64,
}

impl CacheView {
    fn empty(scope: Arc<CacheScope>) -> Self {
        Self {
            scope,
            keys: BTreeSet::new(),
            identity_bytes: 0,
        }
    }

    /// Number of canonical cache keys in the view.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Variable key identity bytes retained by the view.
    #[must_use]
    pub const fn identity_bytes(&self) -> u64 {
        self.identity_bytes
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CacheScope {
    engine: Box<str>,
    engine_version: Box<str>,
    engine_instance: Box<str>,
    publisher: Box<str>,
    data_parallel_rank: u32,
    epoch: Box<str>,
}

impl From<&StreamDeclaration> for CacheScope {
    fn from(stream: &StreamDeclaration) -> Self {
        Self {
            engine: stream.engine.clone().into_boxed_str(),
            engine_version: stream.engine_version.clone().into_boxed_str(),
            engine_instance: stream.engine_instance.clone().into_boxed_str(),
            publisher: stream.publisher.clone().into_boxed_str(),
            data_parallel_rank: stream.data_parallel_rank,
            epoch: stream.epoch.clone().into_boxed_str(),
        }
    }
}

impl CacheScope {
    fn identity_bytes(&self) -> Result<u64, Error> {
        [
            self.engine.len(),
            self.engine_version.len(),
            self.engine_instance.len(),
            self.publisher.len(),
            self.epoch.len(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, length| {
            total
                .checked_add(usize_to_u64(length)?)
                .ok_or(Error::CounterOverflow)
        })
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CacheKey {
    group: CacheGroup,
    medium: StorageMedium,
    hash: OpaqueHash,
}

impl CacheKey {
    const fn new(group: CacheGroup, medium: StorageMedium, hash: OpaqueHash) -> Self {
        Self {
            group,
            medium,
            hash,
        }
    }

    fn identity_bytes(&self) -> Result<u64, Error> {
        let group: u64 = match self.group {
            CacheGroup::Index { .. } => 4,
            CacheGroup::Unspecified => 0,
        };
        let medium = match &self.medium {
            StorageMedium::Named { value } => usize_to_u64(value.len())?,
            StorageMedium::Unspecified => 0,
        };
        let hash = match &self.hash {
            OpaqueHash::U64 { .. } => 8,
            OpaqueHash::Bytes { value } => usize_to_u64(value.as_bytes().len())?,
        };
        group
            .checked_add(medium)
            .and_then(|value| value.checked_add(hash))
            .ok_or(Error::CounterOverflow)
    }
}

/// Atomic cache mutation projection over an immutable base view.
///
/// The overlay retains only changed keys, avoiding a full cache clone for each
/// admitted envelope while keeping every resource check before commit.
struct CacheTransaction<'view> {
    base: &'view CacheView,
    cleared: bool,
    added: BTreeSet<CacheKey>,
    removed: BTreeSet<CacheKey>,
    key_count: usize,
    identity_bytes: u64,
    missing_removes: u64,
}

impl<'view> CacheTransaction<'view> {
    fn new(base: &'view CacheView) -> Self {
        Self {
            base,
            cleared: false,
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
            key_count: base.keys.len(),
            identity_bytes: base.identity_bytes,
            missing_removes: 0,
        }
    }

    fn apply(&mut self, mutations: &[Mutation], limits: &Limits) -> Result<(), Error> {
        for mutation in mutations {
            match mutation {
                Mutation::StoreRun {
                    hashes,
                    group,
                    medium,
                    ..
                } => {
                    for hash in hashes {
                        self.store(CacheKey::new(*group, medium.clone(), hash.clone()), limits)?;
                    }
                }
                Mutation::Remove {
                    hashes,
                    group,
                    medium,
                    ..
                } => {
                    for hash in hashes {
                        self.remove(CacheKey::new(*group, medium.clone(), hash.clone()))?;
                    }
                }
                Mutation::Clear { .. } => self.clear(),
            }
        }
        Ok(())
    }

    fn store(&mut self, key: CacheKey, limits: &Limits) -> Result<(), Error> {
        if self.contains(&key) {
            return Ok(());
        }
        let key_bytes = key.identity_bytes()?;
        let observed_keys = self
            .key_count
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        if observed_keys > limits.max_cache_keys_per_stream {
            return Err(Error::ResourceLimit {
                resource: Resource::CacheKeys,
                maximum: usize_to_u64(limits.max_cache_keys_per_stream)?,
                observed: usize_to_u64(observed_keys)?,
            });
        }
        let observed_bytes = self
            .identity_bytes
            .checked_add(key_bytes)
            .ok_or(Error::CounterOverflow)?;
        if observed_bytes > limits.max_cache_identity_bytes_per_stream {
            return Err(Error::ResourceLimit {
                resource: Resource::CacheIdentityBytes,
                maximum: limits.max_cache_identity_bytes_per_stream,
                observed: observed_bytes,
            });
        }

        if !self.cleared && self.base.keys.contains(&key) {
            let removed = self.removed.remove(&key);
            debug_assert!(removed, "an absent base key must be in the removal overlay");
        } else {
            let inserted = self.added.insert(key);
            debug_assert!(inserted, "an absent projected key must be newly added");
        }
        self.key_count = observed_keys;
        self.identity_bytes = observed_bytes;
        Ok(())
    }

    fn remove(&mut self, key: CacheKey) -> Result<(), Error> {
        if !self.contains(&key) {
            self.missing_removes = self
                .missing_removes
                .checked_add(1)
                .ok_or(Error::CounterOverflow)?;
            return Ok(());
        }
        let key_bytes = key.identity_bytes()?;
        if !self.added.remove(&key) {
            let inserted = self.removed.insert(key);
            debug_assert!(inserted, "a present base key must be newly removed");
        }
        self.key_count = self
            .key_count
            .checked_sub(1)
            .ok_or(Error::CounterOverflow)?;
        self.identity_bytes = self
            .identity_bytes
            .checked_sub(key_bytes)
            .ok_or(Error::CounterOverflow)?;
        Ok(())
    }

    fn clear(&mut self) {
        self.cleared = true;
        self.added.clear();
        self.removed.clear();
        self.key_count = 0;
        self.identity_bytes = 0;
    }

    fn contains(&self, key: &CacheKey) -> bool {
        self.added.contains(key)
            || (!self.cleared && self.base.keys.contains(key) && !self.removed.contains(key))
    }

    fn finish(self) -> CachePlan {
        CachePlan {
            cleared: self.cleared,
            added: self.added,
            removed: self.removed,
            key_count: self.key_count,
            identity_bytes: self.identity_bytes,
            missing_removes: self.missing_removes,
        }
    }
}

struct CachePlan {
    cleared: bool,
    added: BTreeSet<CacheKey>,
    removed: BTreeSet<CacheKey>,
    key_count: usize,
    identity_bytes: u64,
    missing_removes: u64,
}

impl CachePlan {
    fn commit(self, view: &mut CacheView) {
        if self.cleared {
            view.keys.clear();
        } else {
            for key in self.removed {
                let removed = view.keys.remove(&key);
                debug_assert!(removed, "a planned base removal must exist at commit");
            }
        }
        view.keys.extend(self.added);
        view.identity_bytes = self.identity_bytes;
        debug_assert_eq!(view.keys.len(), self.key_count);
    }
}

/// Fixed-size historical diagnostic counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    duplicates: u64,
    equivocations: u64,
    stale_unverifiable: u64,
    stale_barriers: u64,
    missing_removes_exact: u64,
    missing_removes_partial: u64,
    pending_limits: u64,
    gap_limits: u64,
    unverifiable_gaps: u64,
    unclosed_gaps: u64,
    truncated: bool,
}

impl Diagnostics {
    /// Idempotent redeliveries inside fingerprint coverage.
    #[must_use]
    pub const fn duplicates(self) -> u64 {
        self.duplicates
    }

    /// Conflicting payloads for retained cursors.
    #[must_use]
    pub const fn equivocations(self) -> u64 {
        self.equivocations
    }

    /// Old deliveries outside fingerprint coverage.
    #[must_use]
    pub const fn stale_unverifiable(self) -> u64 {
        self.stale_unverifiable
    }

    /// Old clear deliveries that could not establish a forward barrier.
    #[must_use]
    pub const fn stale_barriers(self) -> u64 {
        self.stale_barriers
    }

    /// Removes missing from an authoritative view.
    #[must_use]
    pub const fn missing_removes_exact(self) -> u64 {
        self.missing_removes_exact
    }

    /// Removes missing from a non-authoritative partial view.
    #[must_use]
    pub const fn missing_removes_partial(self) -> u64 {
        self.missing_removes_partial
    }

    /// Deliveries discarded at pending count or byte ceilings.
    #[must_use]
    pub const fn pending_limits(self) -> u64 {
        self.pending_limits
    }

    /// Deliveries discarded beyond the modeled numeric gap span.
    #[must_use]
    pub const fn gap_limits(self) -> u64 {
        self.gap_limits
    }

    /// Deliveries blocked because earlier evidence was discarded.
    #[must_use]
    pub const fn unverifiable_gaps(self) -> u64 {
        self.unverifiable_gaps
    }

    /// Open gaps finalized without enough delivered evidence.
    #[must_use]
    pub const fn unclosed_gaps(self) -> u64 {
        self.unclosed_gaps
    }

    /// At least one diagnostic increment was suppressed or clamped at its ceiling.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.truncated
    }

    fn increment(counter: &mut u64, truncated: &mut bool, maximum: u64) {
        if *counter >= maximum {
            *truncated = true;
        } else {
            *counter += 1;
        }
    }

    fn add(counter: &mut u64, added: u64, truncated: &mut bool, maximum: u64) {
        let available = maximum.saturating_sub(*counter);
        if added > available {
            *counter = maximum;
            *truncated = true;
        } else {
            *counter += added;
        }
    }
}

/// Incremental state for exactly one declared publisher stream and epoch.
pub struct StreamState {
    session: Arc<SessionMarker>,
    limits: Limits,
    stream_id: Arc<str>,
    initial_cursor: u64,
    certainty: Certainty,
    frontier: Option<u64>,
    baseline_unknown: bool,
    view_authoritative: bool,
    poison_ceiling: Option<u64>,
    equivocation_ceiling: Option<u64>,
    unavailable_floor: Option<u64>,
    unavailable_ceiling: Option<u64>,
    view: CacheView,
    pending: BTreeMap<u64, PendingSlot>,
    pending_bytes: u64,
    recent: BTreeMap<u64, RecentSlot>,
    diagnostics: Diagnostics,
    failed: bool,
}

impl StreamState {
    #[cfg(test)]
    fn new(
        declaration: &ValidatedRecord,
        authority: BaselineAuthority,
        normalizer: &mut EnvelopeNormalizer,
    ) -> Result<Self, Error> {
        let blueprint = normalizer.register_stream(declaration, authority)?;
        Ok(Self::from_blueprint(&blueprint))
    }

    fn from_blueprint(blueprint: &StreamBlueprint) -> Self {
        let registration = &blueprint.registration;
        let trusted_empty = registration.authority == BaselineAuthority::TrustDeclaredEmpty;
        debug_assert!(
            !trusted_empty || registration.baseline == Baseline::EmptyAtEngineStart,
            "trusted authority must match an empty-baseline registration"
        );
        Self {
            session: Arc::clone(&blueprint.session),
            limits: blueprint.limits,
            stream_id: Arc::clone(&registration.stream_id),
            initial_cursor: registration.initial_cursor,
            certainty: if trusted_empty {
                Certainty::Exact
            } else {
                Certainty::Unknown
            },
            frontier: None,
            baseline_unknown: !trusted_empty,
            view_authoritative: trusted_empty,
            poison_ceiling: None,
            equivocation_ceiling: None,
            unavailable_floor: None,
            unavailable_ceiling: None,
            view: CacheView::empty(Arc::clone(&registration.scope)),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            recent: BTreeMap::new(),
            diagnostics: Diagnostics::default(),
            failed: false,
        }
    }

    /// Admit one delivery that was normalized exactly once.
    ///
    /// Duplicate, equivocation, stale, and modeled pending-limit conditions are
    /// returned as dispositions. Only host-safety, scope, and cache-view model
    /// exhaustion are hard errors.
    ///
    /// # Errors
    ///
    /// Returns a stable error without partially applying cache mutations.
    pub fn admit(&mut self, source: Arc<PreparedEnvelope>) -> Result<Disposition, Error> {
        if self.failed {
            return Err(Error::StateFailed);
        }
        if self.session.status.load(Ordering::Acquire) == SESSION_FAILED {
            return Err(Error::NormalizerFailed);
        }
        let result = self.admit_inner(source);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Current certainty classification.
    #[must_use]
    pub const fn certainty(&self) -> Certainty {
        self.certainty
    }

    /// Last applied dense cursor, if any.
    #[must_use]
    pub const fn frontier(&self) -> Option<u64> {
        self.frontier
    }

    /// Whether the current cache view is authoritative through its frontier.
    #[must_use]
    pub const fn view_authoritative(&self) -> bool {
        self.view_authoritative
    }

    /// Borrow the opaque comparable cache view.
    #[must_use]
    pub const fn cache_view(&self) -> &CacheView {
        &self.view
    }

    /// Number of retained out-of-order or conflicted cursor slots.
    #[must_use]
    pub fn pending_envelopes(&self) -> usize {
        self.pending.len()
    }

    /// Canonical mutation bytes represented by clean pending candidates.
    #[must_use]
    pub const fn pending_canonical_bytes(&self) -> u64 {
        self.pending_bytes
    }

    /// Number of applied cursors still covered for duplicate detection.
    #[must_use]
    pub fn recent_fingerprints(&self) -> usize {
        self.recent.len()
    }

    /// Content-free historical diagnostics accumulated so far.
    #[must_use]
    pub const fn diagnostics(&self) -> Diagnostics {
        self.diagnostics
    }

    /// Active reasons for current unknown certainty, excluding an open clean gap.
    #[must_use]
    pub const fn unknown_reasons(&self) -> UnknownReasons {
        UnknownReasons::active(
            self.baseline_unknown,
            self.equivocation_ceiling.is_some(),
            self.unavailable_floor.is_some(),
        )
    }

    /// Finalize delivered evidence after its normalization session is sealed.
    ///
    /// # Errors
    ///
    /// Returns a stable error after an earlier hard failure or when the seal
    /// belongs to a different normalization session.
    pub fn finish(mut self, sealed: &SealedSession) -> Result<StreamSummary, Error> {
        if self.failed {
            return Err(Error::StateFailed);
        }
        if !Arc::ptr_eq(&self.session, &sealed.session) {
            return Err(Error::SessionMismatch);
        }
        if self.session.status.load(Ordering::Acquire) != SESSION_SEALED {
            return Err(Error::NormalizerFailed);
        }
        let unclosed_gap = !self.pending.is_empty();
        if unclosed_gap {
            Diagnostics::increment(
                &mut self.diagnostics.unclosed_gaps,
                &mut self.diagnostics.truncated,
                self.limits.max_diagnostic_count,
            );
            self.certainty = Certainty::Unknown;
        }
        let reasons = self.unknown_reasons().with_unclosed_gap(unclosed_gap);
        Ok(StreamSummary {
            certainty: self.certainty,
            frontier: self.frontier,
            view_authoritative: self.view_authoritative,
            view: self.view,
            pending_envelopes: self.pending.len(),
            pending_canonical_bytes: self.pending_bytes,
            recent_fingerprints: self.recent.len(),
            fingerprint_window: self.limits.max_recent_fingerprints_per_stream,
            reasons,
            diagnostics: self.diagnostics,
        })
    }

    fn admit_inner(&mut self, source: Arc<PreparedEnvelope>) -> Result<Disposition, Error> {
        if !Arc::ptr_eq(&self.session, &source.session) {
            return Err(Error::SessionMismatch);
        }
        if source.stream_id.as_ref() != self.stream_id.as_ref() {
            return Err(Error::StreamMismatch);
        }
        let cursor = source.cursor();
        if cursor < self.initial_cursor {
            return Err(Error::CursorBeforeInitial);
        }

        if let Some(disposition) = self.handle_pending_redelivery(&source) {
            return Ok(disposition);
        }
        if self.frontier.is_some_and(|frontier| cursor <= frontier) {
            return Ok(self.handle_past_delivery(&source));
        }
        if self.unavailable_blocks(&source) {
            self.set_unavailable(cursor);
            self.bump_unverifiable_gap();
            self.recompute_certainty();
            return Ok(Disposition::UnverifiableGap);
        }
        if self.eligible_barrier(&source) {
            return self.apply_source(&source, true);
        }
        if self.baseline_unknown && self.frontier.is_none() {
            return self.apply_source(&source, false);
        }

        match self.expected_cursor() {
            Some(expected) if cursor == expected => self.apply_source(&source, false),
            Some(expected) if cursor > expected => Ok(self.buffer(source, expected)),
            _ => Ok(self.handle_past_delivery(&source)),
        }
    }

    fn handle_pending_redelivery(&mut self, source: &Arc<PreparedEnvelope>) -> Option<Disposition> {
        let cursor = source.cursor();
        let classification = match self.pending.get(&cursor)? {
            PendingSlot::Candidate(first) if first.fingerprint == source.fingerprint => {
                PendingRedelivery::Duplicate
            }
            PendingSlot::Candidate(first) => PendingRedelivery::Conflict {
                first: first.fingerprint,
            },
            PendingSlot::Conflict { first, second }
                if *first == source.fingerprint || *second == source.fingerprint =>
            {
                PendingRedelivery::Duplicate
            }
            PendingSlot::Conflict { .. } => PendingRedelivery::AdditionalConflict,
        };

        match classification {
            PendingRedelivery::Duplicate => {
                self.bump_duplicate();
                Some(Disposition::Duplicate)
            }
            PendingRedelivery::Conflict { first } => {
                let removed_bytes = self
                    .pending
                    .get(&cursor)
                    .map_or(0, PendingSlot::canonical_bytes);
                self.pending.insert(
                    cursor,
                    PendingSlot::Conflict {
                        first,
                        second: source.fingerprint,
                    },
                );
                self.pending_bytes = self
                    .pending_bytes
                    .checked_sub(removed_bytes)
                    .expect("a pending candidate's bytes must be accounted");
                self.bump_equivocation();
                self.set_equivocation(cursor, false);
                self.recompute_certainty();
                Some(Disposition::Equivocation)
            }
            PendingRedelivery::AdditionalConflict => {
                self.bump_equivocation();
                self.set_equivocation(cursor, false);
                self.recompute_certainty();
                Some(Disposition::Equivocation)
            }
        }
    }

    fn handle_past_delivery(&mut self, source: &PreparedEnvelope) -> Disposition {
        let cursor = source.cursor();
        let classification = match self.recent.get(&cursor) {
            Some(RecentSlot::Candidate(first)) if *first == source.fingerprint => {
                Some(RecentRedelivery::Duplicate)
            }
            Some(RecentSlot::Candidate(first)) => {
                Some(RecentRedelivery::Conflict { first: *first })
            }
            Some(RecentSlot::Conflict { first, second })
                if *first == source.fingerprint || *second == source.fingerprint =>
            {
                Some(RecentRedelivery::Duplicate)
            }
            Some(RecentSlot::Conflict { .. }) => Some(RecentRedelivery::AdditionalConflict),
            None => None,
        };

        match classification {
            Some(RecentRedelivery::Duplicate) => {
                self.bump_duplicate();
                Disposition::Duplicate
            }
            Some(RecentRedelivery::Conflict { first }) => {
                self.recent.insert(
                    cursor,
                    RecentSlot::Conflict {
                        first,
                        second: source.fingerprint,
                    },
                );
                self.bump_equivocation();
                self.set_equivocation(cursor, true);
                self.recompute_certainty();
                Disposition::Equivocation
            }
            Some(RecentRedelivery::AdditionalConflict) => {
                self.bump_equivocation();
                self.set_equivocation(cursor, true);
                self.recompute_certainty();
                Disposition::Equivocation
            }
            None if source.has_clear() => {
                Diagnostics::increment(
                    &mut self.diagnostics.stale_barriers,
                    &mut self.diagnostics.truncated,
                    self.limits.max_diagnostic_count,
                );
                Disposition::StaleBarrier
            }
            None => {
                Diagnostics::increment(
                    &mut self.diagnostics.stale_unverifiable,
                    &mut self.diagnostics.truncated,
                    self.limits.max_diagnostic_count,
                );
                Disposition::StaleUnverifiable
            }
        }
    }

    fn eligible_barrier(&self, source: &PreparedEnvelope) -> bool {
        if !source.has_clear() {
            return false;
        }
        let cursor = source.cursor();
        if self.frontier.is_some_and(|frontier| cursor <= frontier) {
            return false;
        }
        match self.certainty {
            Certainty::Unknown | Certainty::Recovering => true,
            Certainty::Exact => self
                .expected_cursor()
                .is_some_and(|expected| cursor > expected),
        }
    }

    fn buffer(&mut self, source: Arc<PreparedEnvelope>, expected: u64) -> Disposition {
        let cursor = source.cursor();
        let span = cursor - expected;
        if span > self.limits.max_gap_span_per_stream {
            Diagnostics::increment(
                &mut self.diagnostics.gap_limits,
                &mut self.diagnostics.truncated,
                self.limits.max_diagnostic_count,
            );
            self.set_unavailable(cursor);
            self.recompute_certainty();
            return Disposition::GapLimit;
        }

        let observed_bytes = self.pending_bytes.checked_add(source.canonical_bytes);
        if self.pending.len() >= self.limits.max_pending_envelopes_per_stream
            || observed_bytes.is_none_or(|observed| {
                observed > self.limits.max_pending_canonical_bytes_per_stream
            })
        {
            Diagnostics::increment(
                &mut self.diagnostics.pending_limits,
                &mut self.diagnostics.truncated,
                self.limits.max_diagnostic_count,
            );
            self.set_unavailable(cursor);
            self.recompute_certainty();
            return Disposition::PendingLimit;
        }

        self.pending_bytes = observed_bytes.expect("checked pending bytes were accepted");
        self.pending.insert(cursor, PendingSlot::Candidate(source));
        self.recompute_certainty();
        Disposition::Buffered
    }

    fn apply_source(
        &mut self,
        source: &PreparedEnvelope,
        barrier: bool,
    ) -> Result<Disposition, Error> {
        let start = if barrier {
            source
                .first_clear
                .expect("barrier eligibility requires a clear mutation")
        } else {
            0
        };
        let authoritative = if barrier {
            true
        } else {
            self.view_authoritative
        };
        let plan = self.application_plan(source, start, authoritative, barrier)?;
        self.commit_application(plan, source.cursor(), barrier, authoritative);
        Ok(if barrier {
            Disposition::BarrierApplied
        } else {
            Disposition::Applied
        })
    }

    fn application_plan(
        &self,
        first: &PreparedEnvelope,
        start: usize,
        authoritative: bool,
        barrier: bool,
    ) -> Result<ApplicationPlan, Error> {
        let mut cache = CacheTransaction::new(&self.view);
        cache.apply(&first.mutations[start..], &self.limits)?;
        let mut applied = vec![AppliedFact {
            cursor: first.cursor(),
            fingerprint: first.fingerprint,
        }];
        let mut cursor = first.cursor();
        let barrier_supersedes_unavailable = barrier
            && self
                .unavailable_ceiling
                .is_some_and(|ceiling| first.cursor() > ceiling);

        while let Some(next) = cursor.checked_add(1) {
            if !barrier_supersedes_unavailable
                && self.unavailable_floor.is_some_and(|floor| next >= floor)
            {
                break;
            }
            let Some(PendingSlot::Candidate(source)) = self.pending.get(&next) else {
                break;
            };
            cache.apply(&source.mutations, &self.limits)?;
            applied.push(AppliedFact {
                cursor: next,
                fingerprint: source.fingerprint,
            });
            cursor = next;
        }
        let cache = cache.finish();

        Ok(ApplicationPlan {
            missing_removes: cache.missing_removes,
            cache,
            missing_removes_are_exact: authoritative,
            applied,
        })
    }

    fn commit_application(
        &mut self,
        plan: ApplicationPlan,
        first_cursor: u64,
        barrier: bool,
        authoritative: bool,
    ) {
        if barrier {
            let retained = first_cursor
                .checked_add(1)
                .map_or_else(BTreeMap::new, |next| self.pending.split_off(&next));
            let discarded = std::mem::replace(&mut self.pending, retained);
            let discarded_bytes = pending_bytes(&discarded);
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(discarded_bytes)
                .expect("discarded pending bytes must be part of the total");
            self.recent.clear();
            self.baseline_unknown = false;
            self.view_authoritative = true;
            if self
                .equivocation_ceiling
                .is_some_and(|ceiling| ceiling < first_cursor)
            {
                self.equivocation_ceiling = None;
            }
            if self
                .unavailable_ceiling
                .is_some_and(|ceiling| ceiling < first_cursor)
            {
                self.unavailable_floor = None;
                self.unavailable_ceiling = None;
            }
            self.recompute_poison();
        }

        plan.cache.commit(&mut self.view);
        for (index, fact) in plan.applied.iter().enumerate() {
            if index != 0
                && let Some(slot) = self.pending.remove(&fact.cursor)
            {
                self.pending_bytes = self
                    .pending_bytes
                    .checked_sub(slot.canonical_bytes())
                    .expect("a drained pending candidate's bytes must be accounted");
            }
            self.retain_fingerprint(fact.cursor, fact.fingerprint);
            self.frontier = Some(fact.cursor);
        }
        self.view_authoritative = if barrier { true } else { authoritative };
        if plan.missing_removes_are_exact {
            Diagnostics::add(
                &mut self.diagnostics.missing_removes_exact,
                plan.missing_removes,
                &mut self.diagnostics.truncated,
                self.limits.max_diagnostic_count,
            );
        } else {
            Diagnostics::add(
                &mut self.diagnostics.missing_removes_partial,
                plan.missing_removes,
                &mut self.diagnostics.truncated,
                self.limits.max_diagnostic_count,
            );
        }
        self.recompute_certainty();
    }

    fn retain_fingerprint(&mut self, cursor: u64, fingerprint: SemanticFingerprint) {
        self.recent
            .insert(cursor, RecentSlot::Candidate(fingerprint));
        while self.recent.len() > self.limits.max_recent_fingerprints_per_stream {
            self.recent.pop_first();
        }
    }

    fn expected_cursor(&self) -> Option<u64> {
        self.frontier.map_or(Some(self.initial_cursor), |frontier| {
            frontier.checked_add(1)
        })
    }

    fn set_equivocation(&mut self, cursor: u64, invalidates_view: bool) {
        self.equivocation_ceiling = Some(
            self.equivocation_ceiling
                .map_or(cursor, |current| current.max(cursor)),
        );
        self.recompute_poison();
        if invalidates_view {
            self.view_authoritative = false;
        }
    }

    fn set_unavailable(&mut self, cursor: u64) {
        self.unavailable_floor = Some(
            self.unavailable_floor
                .map_or(cursor, |current| current.min(cursor)),
        );
        self.unavailable_ceiling = Some(
            self.unavailable_ceiling
                .map_or(cursor, |current| current.max(cursor)),
        );
        self.recompute_poison();
    }

    fn recompute_poison(&mut self) {
        self.poison_ceiling = match (self.equivocation_ceiling, self.unavailable_ceiling) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
    }

    fn unavailable_blocks(&self, source: &PreparedEnvelope) -> bool {
        let Some(floor) = self.unavailable_floor else {
            return false;
        };
        let cursor = source.cursor();
        if cursor < floor {
            return false;
        }
        if !source.has_clear() {
            return true;
        }
        self.unavailable_ceiling
            .is_none_or(|ceiling| cursor <= ceiling)
    }

    fn recompute_certainty(&mut self) {
        self.certainty = if self.baseline_unknown || self.poison_ceiling.is_some() {
            Certainty::Unknown
        } else if self.pending.is_empty() {
            Certainty::Exact
        } else {
            Certainty::Recovering
        };
    }

    fn bump_duplicate(&mut self) {
        Diagnostics::increment(
            &mut self.diagnostics.duplicates,
            &mut self.diagnostics.truncated,
            self.limits.max_diagnostic_count,
        );
    }

    fn bump_equivocation(&mut self) {
        Diagnostics::increment(
            &mut self.diagnostics.equivocations,
            &mut self.diagnostics.truncated,
            self.limits.max_diagnostic_count,
        );
    }

    fn bump_unverifiable_gap(&mut self) {
        Diagnostics::increment(
            &mut self.diagnostics.unverifiable_gaps,
            &mut self.diagnostics.truncated,
            self.limits.max_diagnostic_count,
        );
    }
}

/// Final content-free state plus an opaque comparable cache snapshot.
pub struct StreamSummary {
    certainty: Certainty,
    frontier: Option<u64>,
    view_authoritative: bool,
    view: CacheView,
    pending_envelopes: usize,
    pending_canonical_bytes: u64,
    recent_fingerprints: usize,
    fingerprint_window: usize,
    reasons: UnknownReasons,
    diagnostics: Diagnostics,
}

impl StreamSummary {
    /// Final certainty after unresolved gaps are closed as unknown.
    #[must_use]
    pub const fn certainty(&self) -> Certainty {
        self.certainty
    }

    /// Last applied cursor.
    #[must_use]
    pub const fn frontier(&self) -> Option<u64> {
        self.frontier
    }

    /// Whether the cache snapshot is authoritative through its frontier.
    #[must_use]
    pub const fn view_authoritative(&self) -> bool {
        self.view_authoritative
    }

    /// Borrow the opaque comparable cache snapshot.
    #[must_use]
    pub const fn cache_view(&self) -> &CacheView {
        &self.view
    }

    /// Retained unresolved cursor slots.
    #[must_use]
    pub const fn pending_envelopes(&self) -> usize {
        self.pending_envelopes
    }

    /// Canonical bytes represented by clean pending candidates.
    #[must_use]
    pub const fn pending_canonical_bytes(&self) -> u64 {
        self.pending_canonical_bytes
    }

    /// Applied cursors still covered by fingerprints.
    #[must_use]
    pub const fn recent_fingerprints(&self) -> usize {
        self.recent_fingerprints
    }

    /// Configured applied-cursor fingerprint window.
    #[must_use]
    pub const fn fingerprint_window(&self) -> usize {
        self.fingerprint_window
    }

    /// Active reasons that prevented an exact finalized view.
    #[must_use]
    pub const fn unknown_reasons(&self) -> UnknownReasons {
        self.reasons
    }

    /// Historical content-free diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> Diagnostics {
        self.diagnostics
    }
}

enum PendingSlot {
    Candidate(Arc<PreparedEnvelope>),
    Conflict {
        first: SemanticFingerprint,
        second: SemanticFingerprint,
    },
}

impl PendingSlot {
    fn canonical_bytes(&self) -> u64 {
        match self {
            Self::Candidate(source) => source.canonical_bytes,
            Self::Conflict { .. } => 0,
        }
    }
}

enum PendingRedelivery {
    Duplicate,
    Conflict { first: SemanticFingerprint },
    AdditionalConflict,
}

enum RecentSlot {
    Candidate(SemanticFingerprint),
    Conflict {
        first: SemanticFingerprint,
        second: SemanticFingerprint,
    },
}

enum RecentRedelivery {
    Duplicate,
    Conflict { first: SemanticFingerprint },
    AdditionalConflict,
}

struct AppliedFact {
    cursor: u64,
    fingerprint: SemanticFingerprint,
}

struct ApplicationPlan {
    cache: CachePlan,
    missing_removes: u64,
    missing_removes_are_exact: bool,
    applied: Vec<AppliedFact>,
}

const fn validate_depth(limits: &Limits) -> Result<(), Error> {
    if limits.max_depth > MAX_JSON_DEPTH {
        return Err(Error::UnsupportedDepthLimit {
            configured: limits.max_depth,
            maximum: MAX_JSON_DEPTH,
        });
    }
    Ok(())
}

fn map_fingerprint_error(
    error: fingerprint::Error,
    limited_by_trace: bool,
    already_hashed: u64,
) -> Error {
    match error {
        fingerprint::Error::Canonicalization => Error::FingerprintCanonicalization,
        fingerprint::Error::CounterOverflow => Error::CounterOverflow,
        fingerprint::Error::ResourceLimit { maximum, observed } => {
            let maximum = u64::try_from(maximum).unwrap_or(u64::MAX);
            let observed = u64::try_from(observed).unwrap_or(u64::MAX);
            if limited_by_trace {
                Error::ResourceLimit {
                    resource: Resource::FingerprintBytes,
                    maximum: already_hashed.saturating_add(maximum),
                    observed: already_hashed.saturating_add(observed),
                }
            } else {
                Error::ResourceLimit {
                    resource: Resource::CanonicalMutationBytes,
                    maximum,
                    observed,
                }
            }
        }
    }
}

fn pending_bytes(pending: &BTreeMap<u64, PendingSlot>) -> u64 {
    pending
        .values()
        .try_fold(0_u64, |total, slot| {
            total.checked_add(slot.canonical_bytes())
        })
        .expect("a pending subset cannot exceed its checked total")
}

fn usize_to_u64(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::CounterOverflow)
}

#[cfg(test)]
mod tests;
