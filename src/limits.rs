//! Resource ceilings shared by trace decoding and semantic validation.

/// Hard stack-safety ceiling for configured JSON depth.
pub const MAX_JSON_DEPTH: usize = 64;

/// Default limits are intentionally conservative enough for real event batches
/// while keeping record and whole-trace operations bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum JSON payload bytes accepted for one record, excluding newline.
    pub max_line_bytes: usize,
    /// Maximum physical input bytes in one trace, including line terminators.
    pub max_trace_bytes: u64,
    /// Maximum physical records in one trace.
    pub max_records_per_trace: u64,
    /// Maximum publisher stream declarations in one trace.
    pub max_streams_per_trace: u64,
    /// Maximum event envelopes in one trace.
    pub max_envelopes_per_trace: u64,
    /// Maximum independent fault schedules in one trace.
    pub max_fault_schedules_per_trace: u64,
    /// Maximum fault actions summed across all schedules in one trace.
    pub max_fault_actions_per_trace: u64,
    /// Maximum UTF-8 bytes cloned into trace-wide identity indexes.
    pub max_identity_bytes_per_trace: u64,
    /// Maximum original and synthesized occurrences in one schedule namespace.
    pub max_occurrences_per_schedule: u64,
    /// Maximum envelope-prefix plus synthesized-occurrence work across schedules.
    pub max_schedule_work_per_trace: u64,
    /// Maximum canonical mutation bytes hashed across physical source envelopes.
    pub max_fingerprint_bytes_per_trace: u64,
    /// Maximum applied cursor fingerprints retained for one stream.
    pub max_recent_fingerprints_per_stream: usize,
    /// Maximum out-of-order cursor slots retained for one stream.
    pub max_pending_envelopes_per_stream: usize,
    /// Maximum canonical mutation bytes represented by pending envelopes.
    pub max_pending_canonical_bytes_per_stream: u64,
    /// Maximum numeric distance from the next expected cursor to a pending cursor.
    pub max_gap_span_per_stream: u64,
    /// Maximum canonical cache keys retained for one stream.
    pub max_cache_keys_per_stream: usize,
    /// Maximum variable identity bytes retained by one stream's cache view.
    pub max_cache_identity_bytes_per_stream: u64,
    /// Maximum value of each fixed diagnostic counter before truncation.
    pub max_diagnostic_count: u64,
    /// Maximum nested JSON value depth; values above [`MAX_JSON_DEPTH`] are invalid.
    pub max_depth: usize,
    /// Maximum scalar and container values in one record.
    pub max_values: usize,
    /// Maximum UTF-8 bytes in one string or object key.
    pub max_string_bytes: usize,
    /// Maximum UTF-8 bytes in an identity or version field.
    pub max_identity_bytes: usize,
    /// Maximum cumulative UTF-8 bytes across strings and keys in one record.
    pub max_total_string_bytes: usize,
    /// Maximum entries in one JSON array.
    pub max_array_items: usize,
    /// Maximum entries in one JSON object.
    pub max_object_members: usize,
    /// Maximum cache mutations carried by one envelope.
    pub max_mutations_per_envelope: usize,
    /// Maximum cache hashes carried by one store or remove mutation.
    pub max_hashes_per_mutation: usize,
    /// Maximum cache hashes carried by one envelope across all mutations.
    pub max_hashes_per_envelope: usize,
    /// Maximum decoded bytes in an opaque cache hash.
    pub max_opaque_hash_bytes: usize,
    /// Maximum raw token IDs carried by one store mutation.
    pub max_token_ids_per_mutation: usize,
    /// Maximum declared token count for one store mutation.
    pub max_token_count: u64,
    /// Maximum declared cache block size.
    pub max_block_size: u32,
    /// Maximum optional worker labels on one publisher declaration.
    pub max_worker_metadata: usize,
    /// Maximum actions in one materialized fault schedule.
    pub max_fault_actions: usize,
    /// Maximum copies created by one duplicate action.
    pub max_duplicate_copies: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1024 * 1024,
            max_trace_bytes: 64 * 1024 * 1024,
            max_records_per_trace: 100_000,
            max_streams_per_trace: 4_096,
            max_envelopes_per_trace: 65_536,
            max_fault_schedules_per_trace: 1_024,
            max_fault_actions_per_trace: 65_536,
            max_identity_bytes_per_trace: 16 * 1024 * 1024,
            max_occurrences_per_schedule: 131_072,
            max_schedule_work_per_trace: 1_000_000,
            max_fingerprint_bytes_per_trace: 64 * 1024 * 1024,
            max_recent_fingerprints_per_stream: 4_096,
            max_pending_envelopes_per_stream: 1_024,
            max_pending_canonical_bytes_per_stream: 16 * 1024 * 1024,
            max_gap_span_per_stream: 65_536,
            max_cache_keys_per_stream: 262_144,
            max_cache_identity_bytes_per_stream: 64 * 1024 * 1024,
            max_diagnostic_count: 1_000_000,
            max_depth: 32,
            max_values: 65_536,
            max_string_bytes: 16 * 1024,
            max_identity_bytes: 1_024,
            max_total_string_bytes: 512 * 1024,
            max_array_items: 16_384,
            max_object_members: 256,
            max_mutations_per_envelope: 1_024,
            max_hashes_per_mutation: 4_096,
            max_hashes_per_envelope: 8_192,
            max_opaque_hash_bytes: 256,
            max_token_ids_per_mutation: 16_384,
            max_token_count: 1_048_576,
            max_block_size: 1_048_576,
            max_worker_metadata: 256,
            max_fault_actions: 4_096,
            max_duplicate_copies: 1_024,
        }
    }
}
