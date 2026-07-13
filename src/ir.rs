//! Typed, engine-neutral trace records for `kvcrucible.trace/v1alpha1`.
//!
//! Raw record types implement Serde so the bounded codec can convert its strict
//! syntax tree. They are not an untrusted-input boundary. Use
//! [`ValidatedRecord`] and the codec APIs for output. Privacy-bearing aggregate
//! types intentionally do not implement [`Debug`](fmt::Debug).

use std::{collections::BTreeMap, fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{TRACE_FORMAT_VERSION, limits::Limits};

const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// A JSON object whose values cannot contain floating-point numbers.
pub type IrObject = BTreeMap<String, IrValue>;

/// Inert JSON data allowed inside `metadata` and `extensions` objects.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IrValue {
    /// JSON `null`.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// Interoperable signed JSON integer.
    Integer(i64),
    /// UTF-8 string.
    String(String),
    /// Ordered JSON array.
    Array(Vec<Self>),
    /// JSON object.
    Object(IrObject),
}

/// A canonical unsigned 64-bit integer represented as a decimal JSON string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecimalU64(u64);

impl DecimalU64 {
    /// Construct a decimal integer from its numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DecimalU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for DecimalU64 {
    type Err = ScalarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(ScalarError::EmptyDecimal);
        }
        if value.len() > 1 && value.starts_with('0') {
            return Err(ScalarError::LeadingZero);
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ScalarError::InvalidDecimal);
        }

        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| ScalarError::InvalidDecimal)
    }
}

impl Serialize for DecimalU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Canonical RFC 4648 standard-base64 bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Base64Bytes(Vec<u8>);

impl Base64Bytes {
    /// Construct an encoded byte value.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Borrow the decoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return its decoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = STANDARD
            .decode(&encoded)
            .map_err(|_| de::Error::custom(ScalarError::InvalidBase64))?;
        if STANDARD.encode(&decoded) != encoded {
            return Err(de::Error::custom(ScalarError::NonCanonicalBase64));
        }
        Ok(Self(decoded))
    }
}

/// Exactly 32 bytes serialized as 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Construct a digest from raw bytes.
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        decode_sha256(&encoded).map(Self).map_err(de::Error::custom)
    }
}

/// Parse failures for canonical scalar wrappers.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScalarError {
    /// The decimal string was empty.
    #[error("decimal value is empty")]
    EmptyDecimal,
    /// A multi-digit decimal string started with zero.
    #[error("decimal value has a leading zero")]
    LeadingZero,
    /// A decimal string contained invalid syntax or exceeded `u64`.
    #[error("decimal value is invalid or out of range")]
    InvalidDecimal,
    /// Standard base64 decoding failed.
    #[error("base64 value is invalid")]
    InvalidBase64,
    /// Base64 decoded but was not the canonical padded representation.
    #[error("base64 value is not canonical RFC 4648 standard encoding")]
    NonCanonicalBase64,
    /// A digest was not exactly 64 lowercase hexadecimal characters.
    #[error("digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
}

/// Prefix-cache hash whose original wire representation remains part of identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpaqueHash {
    /// Legacy unsigned integer representation.
    U64 {
        /// Canonical decimal-string value.
        value: DecimalU64,
    },
    /// Opaque byte representation.
    Bytes {
        /// Canonical standard-base64 value.
        value: Base64Bytes,
    },
}

/// Trace-level statement about token-data handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Token data is absent.
    Omitted,
    /// Token data uses a keyed digest.
    KeyedDigests,
    /// Token data uses an unkeyed, linkable digest.
    UnkeyedLinkable,
    /// Raw token IDs are present.
    ContainsTokenIds,
}

/// Required first record in a canonical trace.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceHeader {
    /// Trace-format identifier.
    pub format: String,
    /// Trace-local label.
    pub trace_id: String,
    /// Declared token redaction mode.
    pub redaction: RedactionMode,
    /// Capture or fixture producer label.
    pub created_by: String,
    /// Inert namespaced extension data.
    pub extensions: IrObject,
}

/// Trust statement for a publisher's initial cache view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Baseline {
    /// Capture provenance establishes an empty cache before `initial_cursor`.
    EmptyAtEngineStart,
    /// Capture attached after unknown cache history.
    UnknownAtAttach,
}

/// One publisher incarnation with its own cursor domain.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDeclaration {
    /// Trace-local stream reference.
    pub stream_id: String,
    /// Serving-engine family.
    pub engine: String,
    /// Exact source-engine version.
    pub engine_version: String,
    /// Deployment-local engine instance.
    pub engine_instance: String,
    /// Publisher endpoint or capture-safe incarnation label.
    pub publisher: String,
    /// Data-parallel rank associated with this publisher.
    pub data_parallel_rank: u32,
    /// Externally declared restart/capture epoch.
    pub epoch: String,
    /// First valid cursor in the upstream domain.
    pub initial_cursor: DecimalU64,
    /// Initial cache-view trust statement.
    pub baseline: Baseline,
    /// Optional non-identity worker labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_metadata: Vec<String>,
    /// Inert namespaced extension data.
    pub extensions: IrObject,
}

/// Whether an envelope arrived through the live or replay channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Original live delivery.
    Live,
    /// Bounded replay delivery.
    Replay,
}

/// Cache group is explicitly indexed or explicitly unavailable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CacheGroup {
    /// Upstream group index.
    Index {
        /// Non-negative cache-group index.
        value: u32,
    },
    /// The source did not provide a group.
    Unspecified,
}

/// Storage medium is named or explicitly unavailable.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageMedium {
    /// Case-preserved upstream medium name.
    Named {
        /// Upstream value such as `GPU`, `CPU`, or `FS`.
        value: String,
    },
    /// The source did not provide a medium.
    Unspecified,
}

/// Prefix lineage retained only when an adapter can establish its meaning.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lineage {
    /// The first hash descends from the given parent; later hashes form a chain.
    Chain {
        /// Parent of the first hash in the store run.
        parent_of_first: OpaqueHash,
    },
    /// The adapter cannot establish a chain relationship.
    Opaque,
}

/// Algorithm identifier for keyed token evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyedDigestAlgorithm {
    /// HMAC using SHA-256.
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

/// Algorithm identifier for linkable token evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UnkeyedDigestAlgorithm {
    /// SHA-256.
    #[serde(rename = "sha256")]
    Sha256,
}

/// Optional evidence about the tokens represented by one store run.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenEvidence {
    /// Confidentiality-oriented keyed digest.
    KeyedDigest {
        /// Digest algorithm.
        algorithm: KeyedDigestAlgorithm,
        /// Capture-local key label; never the key material.
        key_id: String,
        /// Digest bytes.
        value: Sha256Digest,
    },
    /// Linkable unkeyed digest; this is not a confidentiality control.
    UnkeyedDigest {
        /// Digest algorithm.
        algorithm: UnkeyedDigestAlgorithm,
        /// Digest bytes.
        value: Sha256Digest,
    },
    /// Raw token IDs for explicitly labeled captures.
    TokenIds {
        /// Ordered token IDs.
        values: Vec<u32>,
    },
}

/// Engine-neutral cache metadata mutation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    /// Store one ordered run of cache hashes.
    StoreRun {
        /// Ordered cache hashes.
        hashes: Vec<OpaqueHash>,
        /// Optional lineage evidence; explicit `null` is rejected.
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        lineage: Option<Lineage>,
        /// Optional number of represented tokens; explicit `null` is rejected.
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        token_count: Option<u64>,
        /// Optional token evidence; explicit `null` is rejected.
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        token_evidence: Option<TokenEvidence>,
        /// Optional upstream block size; explicit `null` is rejected.
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        block_size: Option<u32>,
        /// Tagged cache group.
        group: CacheGroup,
        /// Tagged storage medium.
        medium: StorageMedium,
        /// Optional aligned per-hash evidence; explicit `null` is rejected.
        #[serde(
            default,
            deserialize_with = "deserialize_present",
            skip_serializing_if = "Option::is_none"
        )]
        block_metadata: Option<Vec<IrObject>>,
        /// Inert mutation metadata.
        metadata: IrObject,
    },
    /// Remove cache hashes from one group and medium.
    Remove {
        /// Cache hashes to remove.
        hashes: Vec<OpaqueHash>,
        /// Tagged cache group.
        group: CacheGroup,
        /// Tagged storage medium.
        medium: StorageMedium,
        /// Inert mutation metadata.
        metadata: IrObject,
    },
    /// Clear every modeled key in this publisher stream.
    Clear {
        /// Inert mutation metadata.
        metadata: IrObject,
    },
}

/// One source envelope after engine-specific decoding.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    /// Stable trace-local identity used by fault schedules.
    pub envelope_id: String,
    /// Declared publisher stream.
    pub stream_id: String,
    /// Publisher-local cursor.
    pub cursor: DecimalU64,
    /// Live or replay provenance.
    pub origin: Origin,
    /// Ordered cache mutations.
    pub mutations: Vec<Mutation>,
    /// Inert namespaced extension data.
    pub extensions: IrObject,
}

/// Stable reference to an original or synthesized delivery occurrence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryRef {
    /// Stable source envelope identity.
    pub envelope_id: String,
    /// Zero for the original delivery, positive for duplicate copies.
    pub occurrence: u16,
}

/// Deterministic delivery transformation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultAction {
    /// Remove one occurrence from delivery.
    Drop {
        /// Delivery occurrence to remove.
        target: DeliveryRef,
    },
    /// Create stable later occurrences of one delivery.
    Duplicate {
        /// Delivery occurrence to duplicate.
        target: DeliveryRef,
        /// Number of copies to create.
        copies: u16,
    },
    /// Move one occurrence immediately before another.
    MoveBefore {
        /// Delivery occurrence to move.
        target: DeliveryRef,
        /// Existing occurrence used as the insertion anchor.
        anchor: DeliveryRef,
    },
}

/// Fully materialized deterministic fault schedule.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSchedule {
    /// Trace-local schedule identity.
    pub schedule_id: String,
    /// Ordered transformations.
    pub actions: Vec<FaultAction>,
    /// Inert namespaced extension data.
    pub extensions: IrObject,
}

/// One raw top-level trace record.
///
/// Direct deserialization does not enforce duplicate-key or pre-allocation
/// limits. Untrusted bytes must go through the bounded codec.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    /// Trace header.
    TraceHeader(TraceHeader),
    /// Publisher stream declaration.
    Stream(StreamDeclaration),
    /// Cache-event envelope.
    Envelope(EventEnvelope),
    /// Deterministic fault schedule.
    FaultSchedule(FaultSchedule),
}

/// A record that passed semantic validation under explicit limits.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedRecord {
    record: Record,
}

impl ValidatedRecord {
    /// Validate and wrap a raw record.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ValidationError`] when a semantic requirement or
    /// configured ceiling is violated.
    pub fn new(record: Record, limits: &Limits) -> Result<Self, ValidationError> {
        record.validate(limits)?;
        Ok(Self { record })
    }

    /// Borrow the validated raw record.
    #[must_use]
    pub const fn as_record(&self) -> &Record {
        &self.record
    }

    /// Consume the wrapper and return the raw record.
    #[must_use]
    pub fn into_record(self) -> Record {
        self.record
    }
}

impl Serialize for ValidatedRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.record.serialize(serializer)
    }
}

/// Stable semantic-validation failures that never echo untrusted values.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    /// Header names a trace format this binary does not implement.
    #[error("unsupported trace format")]
    UnsupportedFormat,
    /// A required identity or label was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Stable field name.
        field: &'static str,
    },
    /// A field exceeded its byte ceiling.
    #[error("{field} exceeds limit {limit} with observed length {actual}")]
    FieldTooLong {
        /// Stable field name.
        field: &'static str,
        /// Configured ceiling.
        limit: usize,
        /// Observed byte count.
        actual: usize,
    },
    /// A vector exceeded its item ceiling.
    #[error("{field} exceeds limit {limit} with observed count {actual}")]
    TooManyItems {
        /// Stable field name.
        field: &'static str,
        /// Configured ceiling.
        limit: usize,
        /// Observed item count.
        actual: usize,
    },
    /// A store or remove carried no hashes.
    #[error("{operation} requires at least one cache hash")]
    EmptyHashes {
        /// Stable mutation name.
        operation: &'static str,
    },
    /// The decoded byte hash exceeded its ceiling or was empty.
    #[error("opaque byte hash length is outside 1..={limit}, observed {actual}")]
    InvalidOpaqueHashLength {
        /// Configured ceiling.
        limit: usize,
        /// Observed byte count.
        actual: usize,
    },
    /// Aligned per-block metadata did not match the hash count.
    #[error("block metadata count {metadata} does not match hash count {hashes}")]
    BlockMetadataLength {
        /// Number of hashes.
        hashes: usize,
        /// Number of metadata objects.
        metadata: usize,
    },
    /// A token count exceeded its configured ceiling.
    #[error("token count {actual} exceeds limit {limit}")]
    TokenCountExceeded {
        /// Configured ceiling.
        limit: u64,
        /// Observed count.
        actual: u64,
    },
    /// Raw token evidence disagreed with an explicit token count.
    #[error("raw token count {token_ids} does not match declared count {declared}")]
    TokenCountMismatch {
        /// Declared count.
        declared: u64,
        /// Raw vector length.
        token_ids: usize,
    },
    /// A block size was zero or exceeded its ceiling.
    #[error("block size {actual} is outside 1..={limit}")]
    InvalidBlockSize {
        /// Configured ceiling.
        limit: u32,
        /// Observed block size.
        actual: u32,
    },
    /// One envelope exceeded its aggregate hash ceiling.
    #[error("envelope hash count {actual} exceeds limit {limit}")]
    TooManyEnvelopeHashes {
        /// Configured ceiling.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
    /// A JSON integer fell outside the interoperable range.
    #[error("JSON integer is outside the interoperable range")]
    UnsafeJsonInteger,
    /// Nested inert JSON exceeded a configured ceiling.
    #[error("{limit_name} exceeds limit {limit} with observed value {actual}")]
    JsonLimitExceeded {
        /// Stable limit name.
        limit_name: &'static str,
        /// Configured ceiling.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
    /// Duplicate action requested zero or too many copies.
    #[error("duplicate copies {actual} are outside 1..={limit}")]
    InvalidDuplicateCopies {
        /// Configured ceiling.
        limit: u16,
        /// Observed copy count.
        actual: u16,
    },
    /// A reorder action named the same delivery as target and anchor.
    #[error("move_before target and anchor must differ")]
    SameMoveTargetAndAnchor,
}

impl ValidationError {
    /// Machine-stable error code suitable for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "unsupported_format",
            Self::EmptyField { .. } => "empty_field",
            Self::FieldTooLong { .. } => "field_too_long",
            Self::TooManyItems { .. } => "too_many_items",
            Self::EmptyHashes { .. } => "empty_hashes",
            Self::InvalidOpaqueHashLength { .. } => "invalid_opaque_hash_length",
            Self::BlockMetadataLength { .. } => "block_metadata_length",
            Self::TokenCountExceeded { .. } => "token_count_exceeded",
            Self::TokenCountMismatch { .. } => "token_count_mismatch",
            Self::InvalidBlockSize { .. } => "invalid_block_size",
            Self::TooManyEnvelopeHashes { .. } => "too_many_envelope_hashes",
            Self::UnsafeJsonInteger => "unsafe_json_integer",
            Self::JsonLimitExceeded { .. } => "json_limit_exceeded",
            Self::InvalidDuplicateCopies { .. } => "invalid_duplicate_copies",
            Self::SameMoveTargetAndAnchor => "same_move_target_and_anchor",
        }
    }
}

impl Record {
    /// Validate record-local semantics under explicit resource ceilings.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ValidationError`] when a semantic requirement or
    /// configured ceiling is violated.
    pub fn validate(&self, limits: &Limits) -> Result<(), ValidationError> {
        let mut context = ValidationContext::new(limits);

        match self {
            Self::TraceHeader(header) => context.validate_header(header),
            Self::Stream(stream) => context.validate_stream(stream),
            Self::Envelope(envelope) => context.validate_envelope(envelope),
            Self::FaultSchedule(schedule) => context.validate_schedule(schedule),
        }
    }
}

struct ValidationContext<'a> {
    limits: &'a Limits,
    string_bytes: usize,
    json_values: usize,
    envelope_hashes: usize,
}

impl<'a> ValidationContext<'a> {
    const fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            string_bytes: 0,
            json_values: 0,
            envelope_hashes: 0,
        }
    }

    fn validate_header(&mut self, header: &TraceHeader) -> Result<(), ValidationError> {
        if header.format != TRACE_FORMAT_VERSION {
            return Err(ValidationError::UnsupportedFormat);
        }
        self.identity("trace_id", &header.trace_id)?;
        self.identity("created_by", &header.created_by)?;
        self.object(&header.extensions, 1)
    }

    fn validate_stream(&mut self, stream: &StreamDeclaration) -> Result<(), ValidationError> {
        self.identity("stream_id", &stream.stream_id)?;
        self.identity("engine", &stream.engine)?;
        self.identity("engine_version", &stream.engine_version)?;
        self.identity("engine_instance", &stream.engine_instance)?;
        self.identity("publisher", &stream.publisher)?;
        self.identity("epoch", &stream.epoch)?;
        Self::items(
            "worker_metadata",
            stream.worker_metadata.len(),
            self.limits.max_worker_metadata,
        )?;
        for worker in &stream.worker_metadata {
            self.identity("worker_metadata", worker)?;
        }
        self.object(&stream.extensions, 1)
    }

    fn validate_envelope(&mut self, envelope: &EventEnvelope) -> Result<(), ValidationError> {
        self.identity("envelope_id", &envelope.envelope_id)?;
        self.identity("stream_id", &envelope.stream_id)?;
        Self::items(
            "mutations",
            envelope.mutations.len(),
            self.limits.max_mutations_per_envelope,
        )?;
        for mutation in &envelope.mutations {
            self.validate_mutation(mutation)?;
        }
        self.object(&envelope.extensions, 1)
    }

    fn validate_schedule(&mut self, schedule: &FaultSchedule) -> Result<(), ValidationError> {
        self.identity("schedule_id", &schedule.schedule_id)?;
        Self::items(
            "fault_actions",
            schedule.actions.len(),
            self.limits.max_fault_actions,
        )?;
        for action in &schedule.actions {
            match action {
                FaultAction::Drop { target } => self.delivery_ref(target)?,
                FaultAction::Duplicate { target, copies } => {
                    self.delivery_ref(target)?;
                    if *copies == 0 || *copies > self.limits.max_duplicate_copies {
                        return Err(ValidationError::InvalidDuplicateCopies {
                            limit: self.limits.max_duplicate_copies,
                            actual: *copies,
                        });
                    }
                }
                FaultAction::MoveBefore { target, anchor } => {
                    self.delivery_ref(target)?;
                    self.delivery_ref(anchor)?;
                    if target == anchor {
                        return Err(ValidationError::SameMoveTargetAndAnchor);
                    }
                }
            }
        }
        self.object(&schedule.extensions, 1)
    }

    fn validate_mutation(&mut self, mutation: &Mutation) -> Result<(), ValidationError> {
        match mutation {
            Mutation::StoreRun {
                hashes,
                lineage,
                token_count,
                token_evidence,
                block_size,
                group: _,
                medium,
                block_metadata,
                metadata,
            } => {
                self.hashes("store_run", hashes)?;
                if let Some(Lineage::Chain { parent_of_first }) = lineage {
                    self.hash(parent_of_first)?;
                }
                if let Some(count) = token_count
                    && *count > MAX_SAFE_JSON_INTEGER as u64
                {
                    return Err(ValidationError::UnsafeJsonInteger);
                }
                if let Some(count) = token_count
                    && *count > self.limits.max_token_count
                {
                    return Err(ValidationError::TokenCountExceeded {
                        limit: self.limits.max_token_count,
                        actual: *count,
                    });
                }
                if let Some(evidence) = token_evidence {
                    self.token_evidence(evidence, *token_count)?;
                }
                if let Some(size) = block_size
                    && (*size == 0 || *size > self.limits.max_block_size)
                {
                    return Err(ValidationError::InvalidBlockSize {
                        limit: self.limits.max_block_size,
                        actual: *size,
                    });
                }
                self.medium(medium)?;
                if let Some(objects) = block_metadata {
                    if objects.len() != hashes.len() {
                        return Err(ValidationError::BlockMetadataLength {
                            hashes: hashes.len(),
                            metadata: objects.len(),
                        });
                    }
                    for object in objects {
                        self.object(object, 1)?;
                    }
                }
                self.object(metadata, 1)
            }
            Mutation::Remove {
                hashes,
                group: _,
                medium,
                metadata,
            } => {
                self.hashes("remove", hashes)?;
                self.medium(medium)?;
                self.object(metadata, 1)
            }
            Mutation::Clear { metadata } => self.object(metadata, 1),
        }
    }

    fn token_evidence(
        &mut self,
        evidence: &TokenEvidence,
        token_count: Option<u64>,
    ) -> Result<(), ValidationError> {
        match evidence {
            TokenEvidence::KeyedDigest { key_id, .. } => self.identity("key_id", key_id),
            TokenEvidence::UnkeyedDigest { .. } => Ok(()),
            TokenEvidence::TokenIds { values } => {
                Self::items(
                    "token_ids",
                    values.len(),
                    self.limits.max_token_ids_per_mutation,
                )?;
                if let Some(declared) = token_count
                    && usize::try_from(declared).ok() != Some(values.len())
                {
                    return Err(ValidationError::TokenCountMismatch {
                        declared,
                        token_ids: values.len(),
                    });
                }
                Ok(())
            }
        }
    }

    fn hashes(
        &mut self,
        operation: &'static str,
        hashes: &[OpaqueHash],
    ) -> Result<(), ValidationError> {
        if hashes.is_empty() {
            return Err(ValidationError::EmptyHashes { operation });
        }
        Self::items("hashes", hashes.len(), self.limits.max_hashes_per_mutation)?;
        self.envelope_hashes = self.envelope_hashes.saturating_add(hashes.len());
        if self.envelope_hashes > self.limits.max_hashes_per_envelope {
            return Err(ValidationError::TooManyEnvelopeHashes {
                limit: self.limits.max_hashes_per_envelope,
                actual: self.envelope_hashes,
            });
        }
        for hash in hashes {
            self.hash(hash)?;
        }
        Ok(())
    }

    fn hash(&self, hash: &OpaqueHash) -> Result<(), ValidationError> {
        if let OpaqueHash::Bytes { value } = hash {
            let actual = value.as_bytes().len();
            if actual == 0 || actual > self.limits.max_opaque_hash_bytes {
                return Err(ValidationError::InvalidOpaqueHashLength {
                    limit: self.limits.max_opaque_hash_bytes,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn medium(&mut self, medium: &StorageMedium) -> Result<(), ValidationError> {
        if let StorageMedium::Named { value } = medium {
            self.identity("medium", value)?;
        }
        Ok(())
    }

    fn delivery_ref(&mut self, delivery: &DeliveryRef) -> Result<(), ValidationError> {
        self.identity("envelope_id", &delivery.envelope_id)
    }

    fn identity(&mut self, field: &'static str, value: &str) -> Result<(), ValidationError> {
        if value.is_empty() {
            return Err(ValidationError::EmptyField { field });
        }
        let limit = self
            .limits
            .max_identity_bytes
            .min(self.limits.max_string_bytes);
        if value.len() > limit {
            return Err(ValidationError::FieldTooLong {
                field,
                limit,
                actual: value.len(),
            });
        }
        self.add_string_bytes(value.len())
    }

    fn object(&mut self, value: &IrObject, depth: usize) -> Result<(), ValidationError> {
        self.json_value_count(1)?;
        Self::items(
            "object_members",
            value.len(),
            self.limits.max_object_members,
        )?;
        self.depth(depth)?;
        for (key, child) in value {
            self.string(key)?;
            self.value(child, depth + 1)?;
        }
        Ok(())
    }

    fn value(&mut self, value: &IrValue, depth: usize) -> Result<(), ValidationError> {
        match value {
            IrValue::Object(object) => self.object(object, depth),
            IrValue::Null | IrValue::Bool(_) => {
                self.json_value_count(1)?;
                self.depth(depth)
            }
            IrValue::Integer(number) => {
                self.json_value_count(1)?;
                self.depth(depth)?;
                if number.unsigned_abs() > MAX_SAFE_JSON_INTEGER as u64 {
                    return Err(ValidationError::UnsafeJsonInteger);
                }
                Ok(())
            }
            IrValue::String(string) => {
                self.json_value_count(1)?;
                self.depth(depth)?;
                self.string(string)
            }
            IrValue::Array(values) => {
                self.json_value_count(1)?;
                self.depth(depth)?;
                Self::items("array_items", values.len(), self.limits.max_array_items)?;
                for child in values {
                    self.value(child, depth + 1)?;
                }
                Ok(())
            }
        }
    }

    fn string(&mut self, value: &str) -> Result<(), ValidationError> {
        if value.len() > self.limits.max_string_bytes {
            return Err(ValidationError::JsonLimitExceeded {
                limit_name: "string_bytes",
                limit: self.limits.max_string_bytes,
                actual: value.len(),
            });
        }
        self.add_string_bytes(value.len())
    }

    fn add_string_bytes(&mut self, added: usize) -> Result<(), ValidationError> {
        self.string_bytes = self.string_bytes.saturating_add(added);
        if self.string_bytes > self.limits.max_total_string_bytes {
            return Err(ValidationError::JsonLimitExceeded {
                limit_name: "total_string_bytes",
                limit: self.limits.max_total_string_bytes,
                actual: self.string_bytes,
            });
        }
        Ok(())
    }

    fn json_value_count(&mut self, added: usize) -> Result<(), ValidationError> {
        self.json_values = self.json_values.saturating_add(added);
        if self.json_values > self.limits.max_values {
            return Err(ValidationError::JsonLimitExceeded {
                limit_name: "json_values",
                limit: self.limits.max_values,
                actual: self.json_values,
            });
        }
        Ok(())
    }

    fn depth(&self, depth: usize) -> Result<(), ValidationError> {
        if depth > self.limits.max_depth {
            return Err(ValidationError::JsonLimitExceeded {
                limit_name: "json_depth",
                limit: self.limits.max_depth,
                actual: depth,
            });
        }
        Ok(())
    }

    const fn items(
        field: &'static str,
        actual: usize,
        limit: usize,
    ) -> Result<(), ValidationError> {
        if actual > limit {
            return Err(ValidationError::TooManyItems {
                field,
                limit,
                actual,
            });
        }
        Ok(())
    }
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ScalarError> {
    if value.len() != 64 {
        return Err(ScalarError::InvalidDigest);
    }
    let bytes = value.as_bytes();
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or(ScalarError::InvalidDigest)?;
        let low = decode_nibble(pair[1]).ok_or(ScalarError::InvalidDigest)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        Base64Bytes, CacheGroup, DecimalU64, EventEnvelope, IrValue, Mutation, OpaqueHash, Origin,
        Record, ScalarError, Sha256Digest, StorageMedium, ValidationError,
    };
    use crate::limits::Limits;

    fn integer_hash(value: u64) -> OpaqueHash {
        OpaqueHash::U64 {
            value: DecimalU64::new(value),
        }
    }

    fn store(hashes: Vec<OpaqueHash>) -> Mutation {
        Mutation::StoreRun {
            hashes,
            lineage: None,
            token_count: None,
            token_evidence: None,
            block_size: None,
            group: CacheGroup::Unspecified,
            medium: StorageMedium::Unspecified,
            block_metadata: None,
            metadata: BTreeMap::new(),
        }
    }

    fn envelope(mutations: Vec<Mutation>) -> Record {
        Record::Envelope(EventEnvelope {
            envelope_id: "env-1".to_owned(),
            stream_id: "stream-1".to_owned(),
            cursor: DecimalU64::new(0),
            origin: Origin::Live,
            mutations,
            extensions: BTreeMap::new(),
        })
    }

    #[test]
    fn decimal_u64_requires_canonical_string_syntax() {
        assert_eq!("0".parse(), Ok(DecimalU64::new(0)));
        assert_eq!(u64::MAX.to_string().parse(), Ok(DecimalU64::new(u64::MAX)));
        assert_eq!("".parse::<DecimalU64>(), Err(ScalarError::EmptyDecimal));
        assert_eq!("01".parse::<DecimalU64>(), Err(ScalarError::LeadingZero));
        assert_eq!("+1".parse::<DecimalU64>(), Err(ScalarError::InvalidDecimal));
        assert_eq!(
            "18446744073709551616".parse::<DecimalU64>(),
            Err(ScalarError::InvalidDecimal)
        );
    }

    #[test]
    fn base64_bytes_reject_noncanonical_spellings() {
        let parsed: OpaqueHash = serde_json::from_value(json!({
            "encoding": "bytes",
            "value": "AAECAwQ="
        }))
        .unwrap();
        assert_eq!(
            parsed,
            OpaqueHash::Bytes {
                value: Base64Bytes::new(vec![0, 1, 2, 3, 4])
            }
        );

        for invalid in ["AAECAwQ", "AAECAwQ_", " AAECAwQ="] {
            let result = serde_json::from_value::<OpaqueHash>(json!({
                "encoding": "bytes",
                "value": invalid
            }));
            assert!(result.is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn every_optional_store_field_rejects_explicit_null() {
        let base = json!({
            "op": "store_run",
            "hashes": [{"encoding": "u64", "value": "1"}],
            "group": {"kind": "unspecified"},
            "medium": {"kind": "unspecified"},
            "metadata": {}
        });

        for field in [
            "lineage",
            "token_count",
            "token_evidence",
            "block_size",
            "block_metadata",
        ] {
            let mut input = base.clone();
            input
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::Value::Null);
            assert!(
                serde_json::from_value::<Mutation>(input).is_err(),
                "accepted null for {field}"
            );
        }
    }

    #[test]
    fn sha256_digest_requires_exact_lowercase_hex() {
        let valid = "00".repeat(32);
        let parsed: Sha256Digest = serde_json::from_str(&format!("\"{valid}\"")).unwrap();
        assert_eq!(parsed, Sha256Digest::new([0; 32]));

        for invalid in ["0".repeat(63), "A0".repeat(32), "gg".repeat(32)] {
            assert!(serde_json::from_str::<Sha256Digest>(&format!("\"{invalid}\"")).is_err());
        }
    }

    #[test]
    fn core_unknown_fields_fail_closed() {
        let result = serde_json::from_value::<Record>(json!({
            "kind": "envelope",
            "envelope_id": "env-1",
            "stream_id": "stream-1",
            "cursor": "0",
            "origin": "live",
            "mutations": [],
            "extensions": {},
            "typo": true
        }));

        assert!(result.is_err());
    }

    #[test]
    fn validation_rejects_empty_hash_runs() {
        let error = envelope(vec![store(Vec::new())])
            .validate(&Limits::default())
            .unwrap_err();

        assert_eq!(
            error,
            ValidationError::EmptyHashes {
                operation: "store_run"
            }
        );
        assert_eq!(error.code(), "empty_hashes");
    }

    #[test]
    fn validation_rejects_misaligned_block_metadata() {
        let mut mutation = store(vec![integer_hash(1), integer_hash(2)]);
        let Mutation::StoreRun { block_metadata, .. } = &mut mutation else {
            unreachable!();
        };
        *block_metadata = Some(vec![BTreeMap::new()]);

        assert_eq!(
            envelope(vec![mutation]).validate(&Limits::default()),
            Err(ValidationError::BlockMetadataLength {
                hashes: 2,
                metadata: 1
            })
        );
    }

    #[test]
    fn inert_metadata_rejects_unsafe_integers() {
        let mut metadata = BTreeMap::new();
        metadata.insert("unsafe".to_owned(), IrValue::Integer(9_007_199_254_740_992));
        let mutation = Mutation::Clear { metadata };

        assert_eq!(
            envelope(vec![mutation]).validate(&Limits::default()),
            Err(ValidationError::UnsafeJsonInteger)
        );
    }

    #[test]
    fn token_count_is_always_an_interoperable_json_integer() {
        let mut mutation = store(vec![integer_hash(1)]);
        let Mutation::StoreRun { token_count, .. } = &mut mutation else {
            unreachable!();
        };
        *token_count = Some(9_007_199_254_740_992);
        let limits = Limits {
            max_token_count: u64::MAX,
            ..Limits::default()
        };

        assert_eq!(
            envelope(vec![mutation]).validate(&limits),
            Err(ValidationError::UnsafeJsonInteger)
        );
    }

    #[test]
    fn valid_envelope_round_trips_through_serde() {
        let record = envelope(vec![store(vec![integer_hash(7)])]);
        record.validate(&Limits::default()).unwrap();

        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: Record = serde_json::from_slice(&encoded).unwrap();

        assert!(decoded == record);
    }
}
