use std::{collections::BTreeMap, sync::Arc};

use proptest::prelude::*;

use super::{
    BaselineAuthority, Certainty, Disposition, EnvelopeNormalizer, Error, PreparedEnvelope,
    Resource, StreamState,
};
use crate::{
    ir::{
        Base64Bytes, Baseline, CacheGroup, DecimalU64, EventEnvelope, IrValue, Mutation,
        OpaqueHash, Origin, Record, StorageMedium, StreamDeclaration, ValidatedRecord,
        ValidationError,
    },
    limits::{Limits, MAX_JSON_DEPTH},
};

fn validated(record: Record) -> ValidatedRecord {
    ValidatedRecord::new(record, &Limits::default()).unwrap()
}

fn declaration(baseline: Baseline, initial_cursor: u64) -> ValidatedRecord {
    declaration_for("stream-a", "instance", baseline, initial_cursor)
}

fn declaration_for(
    stream_id: &str,
    engine_instance: &str,
    baseline: Baseline,
    initial_cursor: u64,
) -> ValidatedRecord {
    validated(Record::Stream(StreamDeclaration {
        stream_id: stream_id.to_owned(),
        engine: "engine".to_owned(),
        engine_version: "1".to_owned(),
        engine_instance: engine_instance.to_owned(),
        publisher: "publisher".to_owned(),
        data_parallel_rank: 0,
        epoch: "epoch".to_owned(),
        initial_cursor: DecimalU64::new(initial_cursor),
        baseline,
        worker_metadata: Vec::new(),
        extensions: BTreeMap::new(),
    }))
}

fn raw_envelope(
    envelope_id: &str,
    stream_id: &str,
    cursor: u64,
    origin: Origin,
    mutations: Vec<Mutation>,
) -> EventEnvelope {
    EventEnvelope {
        envelope_id: envelope_id.to_owned(),
        stream_id: stream_id.to_owned(),
        cursor: DecimalU64::new(cursor),
        origin,
        mutations,
        extensions: BTreeMap::new(),
    }
}

fn prepare(
    normalizer: &mut EnvelopeNormalizer,
    envelope_id: &str,
    cursor: u64,
    mutations: Vec<Mutation>,
) -> Arc<PreparedEnvelope> {
    prepare_for(
        normalizer,
        envelope_id,
        "stream-a",
        cursor,
        Origin::Live,
        mutations,
    )
}

fn prepare_for(
    normalizer: &mut EnvelopeNormalizer,
    envelope_id: &str,
    stream_id: &str,
    cursor: u64,
    origin: Origin,
    mutations: Vec<Mutation>,
) -> Arc<PreparedEnvelope> {
    normalizer
        .prepare(validated(Record::Envelope(raw_envelope(
            envelope_id,
            stream_id,
            cursor,
            origin,
            mutations,
        ))))
        .unwrap()
}

fn integer_hash(value: u64) -> OpaqueHash {
    OpaqueHash::U64 {
        value: DecimalU64::new(value),
    }
}

fn store(value: u64) -> Mutation {
    store_at(
        integer_hash(value),
        CacheGroup::Unspecified,
        StorageMedium::Unspecified,
    )
}

fn store_at(hash: OpaqueHash, group: CacheGroup, medium: StorageMedium) -> Mutation {
    Mutation::StoreRun {
        hashes: vec![hash],
        lineage: None,
        token_count: None,
        token_evidence: None,
        block_size: None,
        group,
        medium,
        block_metadata: None,
        metadata: BTreeMap::new(),
    }
}

fn store_many(values: &[u64]) -> Mutation {
    Mutation::StoreRun {
        hashes: values.iter().copied().map(integer_hash).collect(),
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

fn remove(value: u64) -> Mutation {
    Mutation::Remove {
        hashes: vec![integer_hash(value)],
        group: CacheGroup::Unspecified,
        medium: StorageMedium::Unspecified,
        metadata: BTreeMap::new(),
    }
}

fn clear() -> Mutation {
    Mutation::Clear {
        metadata: BTreeMap::new(),
    }
}

fn trusted_state(normalizer: &mut EnvelopeNormalizer, initial_cursor: u64) -> StreamState {
    StreamState::new(
        &declaration(Baseline::EmptyAtEngineStart, initial_cursor),
        BaselineAuthority::TrustDeclaredEmpty,
        normalizer,
    )
    .unwrap()
}

fn unknown_state(normalizer: &mut EnvelopeNormalizer, initial_cursor: u64) -> StreamState {
    StreamState::new(
        &declaration(Baseline::UnknownAtAttach, initial_cursor),
        BaselineAuthority::TreatAsUnknown,
        normalizer,
    )
    .unwrap()
}

#[test]
fn baseline_requires_external_authority_and_initialization_is_total() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let raw_empty = declaration(Baseline::EmptyAtEngineStart, 5);
    let trusted = StreamState::new(
        &raw_empty,
        BaselineAuthority::TrustDeclaredEmpty,
        &mut normalizer,
    )
    .unwrap();
    assert_eq!(trusted.certainty(), Certainty::Exact);
    assert!(trusted.view_authoritative());

    let mut downgraded_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let downgraded = StreamState::new(
        &raw_empty,
        BaselineAuthority::TreatAsUnknown,
        &mut downgraded_normalizer,
    )
    .unwrap();
    assert_eq!(downgraded.certainty(), Certainty::Unknown);
    assert!(!downgraded.view_authoritative());

    let mut mismatch_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    assert_eq!(
        StreamState::new(
            &declaration(Baseline::UnknownAtAttach, 5),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut mismatch_normalizer,
        )
        .err(),
        Some(Error::BaselineAuthorityMismatch)
    );
    let mismatch_is_non_sticky = StreamState::new(
        &declaration(Baseline::UnknownAtAttach, 5),
        BaselineAuthority::TreatAsUnknown,
        &mut mismatch_normalizer,
    )
    .unwrap();
    let mismatch_seal = mismatch_normalizer.seal().unwrap();
    assert_eq!(
        mismatch_is_non_sticky
            .finish(&mismatch_seal)
            .unwrap()
            .certainty(),
        Certainty::Unknown
    );

    let mut trusted = trusted_state(&mut normalizer, 5);
    let future = prepare(&mut normalizer, "future", 7, vec![store(7)]);
    assert_eq!(trusted.admit(future).unwrap(), Disposition::Buffered);
    assert_eq!(trusted.certainty(), Certainty::Recovering);
    assert_eq!(trusted.frontier(), None);
    assert_eq!(trusted.cache_view().key_count(), 0);

    let mut unknown_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let mut unknown = unknown_state(&mut unknown_normalizer, 5);
    let first = prepare(&mut unknown_normalizer, "unknown-first", 7, vec![store(7)]);
    assert_eq!(unknown.admit(first).unwrap(), Disposition::Applied);
    assert_eq!(unknown.frontier(), Some(7));
    assert_eq!(unknown.certainty(), Certainty::Unknown);
    assert!(unknown.unknown_reasons().baseline());
    assert!(!unknown.view_authoritative());
    assert_eq!(unknown.cache_view().key_count(), 1);
}

#[test]
fn first_forward_clear_can_anchor_trusted_gap_or_unknown_attach() {
    let limits = Limits::default();
    let mut trusted_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let trusted_barrier = prepare(
        &mut trusted_normalizer,
        "barrier",
        9,
        vec![store(1), clear(), store(2)],
    );

    let mut trusted = trusted_state(&mut trusted_normalizer, 5);
    assert_eq!(
        trusted.admit(trusted_barrier).unwrap(),
        Disposition::BarrierApplied
    );
    assert_eq!(trusted.certainty(), Certainty::Exact);
    assert_eq!(trusted.frontier(), Some(9));
    assert_eq!(trusted.cache_view().key_count(), 1);

    let mut unknown_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let unknown_barrier = prepare(
        &mut unknown_normalizer,
        "barrier",
        9,
        vec![store(1), clear(), store(2)],
    );
    let mut unknown = unknown_state(&mut unknown_normalizer, 5);
    assert_eq!(
        unknown.admit(unknown_barrier).unwrap(),
        Disposition::BarrierApplied
    );
    assert_eq!(unknown.certainty(), Certainty::Exact);
    assert!(unknown.view_authoritative());
    assert_eq!(unknown.frontier(), Some(9));
}

#[test]
fn maximum_cursor_is_terminal_without_wrapping_the_successor() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let delivery = prepare(&mut normalizer, "maximum", u64::MAX, vec![store(1)]);
    let mut state = trusted_state(&mut normalizer, u64::MAX);

    assert_eq!(
        state.admit(Arc::clone(&delivery)).unwrap(),
        Disposition::Applied
    );
    assert_eq!(state.frontier(), Some(u64::MAX));
    assert_eq!(state.admit(delivery).unwrap(), Disposition::Duplicate);
    assert_eq!(state.certainty(), Certainty::Exact);
}

#[test]
fn gaps_buffer_without_early_mutation_and_drain_in_dense_order() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let three = prepare(&mut normalizer, "three", 3, vec![store(3)]);
    let two = prepare_for(
        &mut normalizer,
        "two",
        "stream-a",
        2,
        Origin::Replay,
        vec![store(2)],
    );
    let one = prepare(&mut normalizer, "one", 1, vec![store(1)]);
    let mut state = trusted_state(&mut normalizer, 1);

    assert_eq!(state.admit(three).unwrap(), Disposition::Buffered);
    assert_eq!(state.admit(two).unwrap(), Disposition::Buffered);
    assert_eq!(state.cache_view().key_count(), 0);
    assert_eq!(state.pending_envelopes(), 2);
    assert_eq!(state.certainty(), Certainty::Recovering);

    assert_eq!(state.admit(one).unwrap(), Disposition::Applied);
    assert_eq!(state.frontier(), Some(3));
    assert_eq!(state.cache_view().key_count(), 3);
    assert_eq!(state.pending_envelopes(), 0);
    assert_eq!(state.pending_canonical_bytes(), 0);
    assert_eq!(state.certainty(), Certainty::Exact);
}

#[test]
fn finish_turns_an_unclosed_gap_into_bounded_unknown_evidence() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let future = prepare(&mut normalizer, "future", 3, vec![store(3)]);
    let mut state = trusted_state(&mut normalizer, 1);
    state.admit(future).unwrap();

    let sealed = normalizer.seal().unwrap();
    let summary = state.finish(&sealed).unwrap();
    assert_eq!(summary.certainty(), Certainty::Unknown);
    assert_eq!(summary.frontier(), None);
    assert_eq!(summary.pending_envelopes(), 1);
    assert_eq!(summary.diagnostics().unclosed_gaps(), 1);
    assert!(summary.unknown_reasons().unclosed_gap());
    assert!(!summary.unknown_reasons().baseline());
}

#[test]
fn applied_duplicate_and_equivocation_keep_only_the_first_path() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first = prepare(&mut normalizer, "first", 0, vec![store(1)]);
    let same = prepare_for(
        &mut normalizer,
        "same-payload",
        "stream-a",
        0,
        Origin::Replay,
        vec![store(1)],
    );
    let conflict = prepare(&mut normalizer, "conflict", 0, vec![store(2)]);
    let repeated_conflict = prepare(&mut normalizer, "conflict-replay", 0, vec![store(2)]);
    let repeated_first = prepare(&mut normalizer, "first-replay", 0, vec![store(1)]);
    let third_variant = prepare(&mut normalizer, "third-variant", 0, vec![store(3)]);
    let mut state = trusted_state(&mut normalizer, 0);

    assert_eq!(state.admit(first).unwrap(), Disposition::Applied);
    assert_eq!(state.admit(same).unwrap(), Disposition::Duplicate);
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.diagnostics().duplicates(), 1);

    assert_eq!(state.admit(conflict).unwrap(), Disposition::Equivocation);
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.frontier(), Some(0));
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert!(state.unknown_reasons().equivocation());
    assert!(!state.view_authoritative());
    assert_eq!(
        state.admit(repeated_conflict).unwrap(),
        Disposition::Duplicate
    );
    assert_eq!(state.admit(repeated_first).unwrap(), Disposition::Duplicate);
    assert_eq!(
        state.admit(third_variant).unwrap(),
        Disposition::Equivocation
    );
    assert_eq!(state.diagnostics().duplicates(), 3);
    assert_eq!(state.diagnostics().equivocations(), 2);
}

#[test]
fn pending_conflict_applies_neither_payload_and_blocks_dense_drain() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first_two = prepare(&mut normalizer, "two-a", 2, vec![store(2)]);
    let same_two = prepare(&mut normalizer, "two-a-replay", 2, vec![store(2)]);
    let second_two = prepare(&mut normalizer, "two-b", 2, vec![store(20)]);
    let third_two = prepare(&mut normalizer, "two-c", 2, vec![store(200)]);
    let one = prepare(&mut normalizer, "one", 1, vec![store(1)]);
    let mut state = trusted_state(&mut normalizer, 1);

    assert_eq!(state.admit(first_two).unwrap(), Disposition::Buffered);
    assert_eq!(state.admit(same_two).unwrap(), Disposition::Duplicate);
    assert_eq!(state.admit(second_two).unwrap(), Disposition::Equivocation);
    assert_eq!(state.pending_envelopes(), 1);
    assert_eq!(state.pending_canonical_bytes(), 0);
    assert_eq!(state.admit(third_two).unwrap(), Disposition::Equivocation);

    assert_eq!(state.admit(one).unwrap(), Disposition::Applied);
    assert_eq!(state.frontier(), Some(1));
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.pending_envelopes(), 1);
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert!(state.unknown_reasons().equivocation());
}

#[test]
fn fingerprint_window_evicts_old_applied_cursors_but_not_for_pending_arrivals() {
    let limits = Limits {
        max_recent_fingerprints_per_stream: 2,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let zero = prepare(&mut normalizer, "zero", 0, vec![store(0)]);
    let one = prepare(&mut normalizer, "one", 1, vec![store(1)]);
    let two = prepare(&mut normalizer, "two", 2, vec![store(2)]);
    let future = prepare(&mut normalizer, "future", 4, vec![store(4)]);
    let old = prepare(&mut normalizer, "old", 0, vec![store(0)]);
    let retained_conflict = prepare(&mut normalizer, "one-conflict", 1, vec![store(10)]);
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(zero).unwrap();
    state.admit(one).unwrap();
    state.admit(two).unwrap();
    assert_eq!(state.recent_fingerprints(), 2);
    assert_eq!(state.admit(future).unwrap(), Disposition::Buffered);
    assert_eq!(state.recent_fingerprints(), 2);
    assert_eq!(state.admit(old).unwrap(), Disposition::StaleUnverifiable);
    assert_eq!(
        state.admit(retained_conflict).unwrap(),
        Disposition::Equivocation
    );
}

#[test]
fn zero_fingerprint_window_reports_all_old_redelivery_as_unverifiable() {
    let limits = Limits {
        max_recent_fingerprints_per_stream: 0,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first = prepare(&mut normalizer, "first", 0, vec![store(1)]);
    let replay = prepare(&mut normalizer, "replay", 0, vec![store(1)]);
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(first).unwrap();
    assert_eq!(state.recent_fingerprints(), 0);
    assert_eq!(state.admit(replay).unwrap(), Disposition::StaleUnverifiable);
    assert_eq!(state.diagnostics().duplicates(), 0);
}

#[test]
fn clear_barrier_ignores_prefix_and_missing_remove_diagnostics() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let barrier = prepare(
        &mut normalizer,
        "barrier",
        5,
        vec![remove(99), store(1), clear(), store(2)],
    );
    let mut state = unknown_state(&mut normalizer, 0);

    assert_eq!(state.admit(barrier).unwrap(), Disposition::BarrierApplied);
    assert_eq!(state.certainty(), Certainty::Exact);
    assert!(state.unknown_reasons().is_empty());
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.diagnostics().missing_removes_exact(), 0);
    assert_eq!(state.diagnostics().missing_removes_partial(), 0);
}

#[test]
fn later_clear_in_one_barrier_envelope_dominates_earlier_suffix_state() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let barrier = prepare(
        &mut normalizer,
        "barrier",
        5,
        vec![clear(), store(1), clear(), store(2)],
    );
    let mut state = unknown_state(&mut normalizer, 0);

    state.admit(barrier).unwrap();
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.frontier(), Some(5));
}

#[test]
fn clear_below_pending_conflict_keeps_unknown_but_clear_above_resolves_it() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let two_a = prepare(&mut normalizer, "two-a", 2, vec![store(2)]);
    let two_b = prepare(&mut normalizer, "two-b", 2, vec![store(20)]);
    let clear_one = prepare(&mut normalizer, "clear-one", 1, vec![clear(), store(1)]);
    let clear_three = prepare(&mut normalizer, "clear-three", 3, vec![clear(), store(3)]);
    let mut state = trusted_state(&mut normalizer, 1);

    state.admit(two_a).unwrap();
    state.admit(two_b).unwrap();
    assert_eq!(state.admit(clear_one).unwrap(), Disposition::BarrierApplied);
    assert_eq!(state.frontier(), Some(1));
    assert_eq!(state.pending_envelopes(), 1);
    assert_eq!(state.certainty(), Certainty::Unknown);

    assert_eq!(
        state.admit(clear_three).unwrap(),
        Disposition::BarrierApplied
    );
    assert_eq!(state.frontier(), Some(3));
    assert_eq!(state.pending_envelopes(), 0);
    assert_eq!(state.certainty(), Certainty::Exact);
    assert_eq!(state.cache_view().key_count(), 1);
}

#[test]
fn post_barrier_old_traffic_is_stale_but_barrier_cursor_conflict_is_detected() {
    let limits = Limits {
        max_recent_fingerprints_per_stream: 2,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let old = prepare(&mut normalizer, "old", 0, vec![store(0)]);
    let barrier = prepare(&mut normalizer, "barrier", 3, vec![clear(), store(3)]);
    let old_changed = prepare(&mut normalizer, "old-changed", 0, vec![store(10)]);
    let barrier_changed = prepare(
        &mut normalizer,
        "barrier-changed",
        3,
        vec![clear(), store(30)],
    );
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(old).unwrap();
    state.admit(barrier).unwrap();
    assert_eq!(
        state.admit(old_changed).unwrap(),
        Disposition::StaleUnverifiable
    );
    assert_eq!(state.certainty(), Certainty::Exact);
    assert_eq!(
        state.admit(barrier_changed).unwrap(),
        Disposition::Equivocation
    );
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert!(state.unknown_reasons().equivocation());
}

#[test]
fn stale_clear_obeys_duplicate_equivocation_then_window_precedence() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let original = prepare(&mut normalizer, "original", 0, vec![clear(), store(1)]);
    let same = prepare(&mut normalizer, "same", 0, vec![clear(), store(1)]);
    let changed = prepare(&mut normalizer, "changed", 0, vec![clear(), store(2)]);
    let mut state = unknown_state(&mut normalizer, 0);
    state.admit(original).unwrap();
    assert_eq!(state.admit(same).unwrap(), Disposition::Duplicate);
    assert_eq!(state.admit(changed).unwrap(), Disposition::Equivocation);

    let zero_window = Limits {
        max_recent_fingerprints_per_stream: 0,
        ..limits
    };
    let mut normalizer = EnvelopeNormalizer::new(zero_window).unwrap();
    let original = prepare(&mut normalizer, "original-2", 0, vec![clear()]);
    let stale_clear = prepare(&mut normalizer, "stale", 0, vec![clear()]);
    let mut state = unknown_state(&mut normalizer, 0);
    state.admit(original).unwrap();
    assert_eq!(state.admit(stale_clear).unwrap(), Disposition::StaleBarrier);
}

#[test]
fn pending_count_bytes_and_gap_span_have_deterministic_boundaries() {
    let no_pending = Limits {
        max_pending_envelopes_per_stream: 0,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(no_pending).unwrap();
    let future = prepare(&mut normalizer, "future", 2, vec![store(2)]);
    let mut state = trusted_state(&mut normalizer, 0);
    assert_eq!(state.admit(future).unwrap(), Disposition::PendingLimit);
    assert_eq!(state.pending_envelopes(), 0);
    assert_eq!(state.certainty(), Certainty::Unknown);

    let base = Limits::default();
    let mut sizing_normalizer = EnvelopeNormalizer::new(base).unwrap();
    let exact_bytes = prepare(&mut sizing_normalizer, "sizing", 2, vec![store(2)]).canonical_bytes;
    let byte_limited = Limits {
        max_pending_canonical_bytes_per_stream: exact_bytes,
        ..base
    };
    let mut normalizer = EnvelopeNormalizer::new(byte_limited).unwrap();
    let two = prepare(&mut normalizer, "two", 2, vec![store(2)]);
    let three = prepare(&mut normalizer, "three", 3, vec![store(3)]);
    let mut state = trusted_state(&mut normalizer, 0);
    assert_eq!(
        state.admit(Arc::clone(&two)).unwrap(),
        Disposition::Buffered
    );
    assert_eq!(state.pending_canonical_bytes(), exact_bytes);
    assert_eq!(state.admit(three).unwrap(), Disposition::PendingLimit);
    assert_eq!(state.pending_canonical_bytes(), exact_bytes);

    let span_limited = Limits {
        max_gap_span_per_stream: 1,
        ..base
    };
    let mut normalizer = EnvelopeNormalizer::new(span_limited).unwrap();
    let mut state = trusted_state(&mut normalizer, 0);
    let at_limit = prepare(&mut normalizer, "at-limit", 1, vec![store(1)]);
    assert_eq!(state.admit(at_limit).unwrap(), Disposition::Buffered);
    let too_far = prepare(&mut normalizer, "too-far", 2, vec![store(2)]);
    assert_eq!(state.admit(too_far).unwrap(), Disposition::GapLimit);
    assert_eq!(state.diagnostics().gap_limits(), 1);
}

#[test]
fn discarded_gap_evidence_blocks_substitution_until_a_later_clear_anchor() {
    let limits = Limits {
        max_pending_envelopes_per_stream: 0,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let discarded = prepare(&mut normalizer, "discarded", 2, vec![store(2)]);
    let zero = prepare(&mut normalizer, "zero", 0, vec![store(0)]);
    let one = prepare(&mut normalizer, "one", 1, vec![store(1)]);
    let substitute = prepare(&mut normalizer, "substitute", 2, vec![store(99)]);
    let skip_past_gap = prepare(&mut normalizer, "skip", 3, vec![store(3)]);
    let ambiguous_clear = prepare(&mut normalizer, "ambiguous-clear", 2, vec![clear()]);
    let blocked_clear = prepare(&mut normalizer, "blocked-clear", 3, vec![clear(), store(3)]);
    let later_clear = prepare(&mut normalizer, "later-clear", 4, vec![clear(), store(4)]);
    let mut state = trusted_state(&mut normalizer, 0);

    assert_eq!(state.admit(discarded).unwrap(), Disposition::PendingLimit);
    assert_eq!(state.admit(zero).unwrap(), Disposition::Applied);
    assert_eq!(state.admit(one).unwrap(), Disposition::Applied);
    assert_eq!(state.frontier(), Some(1));
    assert_eq!(state.cache_view().key_count(), 2);
    assert_eq!(
        state.admit(substitute).unwrap(),
        Disposition::UnverifiableGap
    );
    assert_eq!(
        state.admit(skip_past_gap).unwrap(),
        Disposition::UnverifiableGap
    );
    assert_eq!(
        state.admit(ambiguous_clear).unwrap(),
        Disposition::UnverifiableGap
    );
    assert_eq!(state.frontier(), Some(1));
    assert_eq!(state.diagnostics().unverifiable_gaps(), 3);
    assert_eq!(
        state.admit(blocked_clear).unwrap(),
        Disposition::UnverifiableGap
    );
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert!(state.unknown_reasons().unavailable_gap());

    assert_eq!(
        state.admit(later_clear).unwrap(),
        Disposition::BarrierApplied
    );
    assert_eq!(state.frontier(), Some(4));
    assert_eq!(state.certainty(), Certainty::Exact);
    assert!(state.view_authoritative());
    assert_eq!(state.cache_view().key_count(), 1);
}

#[test]
fn diagnostic_counters_truncate_without_unbounded_evidence() {
    let limits = Limits {
        max_recent_fingerprints_per_stream: 0,
        max_diagnostic_count: 0,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first = prepare(&mut normalizer, "first", 0, vec![store(1)]);
    let old_delivery = prepare(&mut normalizer, "stale", 0, vec![store(1)]);
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(first).unwrap();
    state.admit(old_delivery).unwrap();
    assert_eq!(state.diagnostics().stale_unverifiable(), 0);
    assert!(state.diagnostics().truncated());
}

#[test]
fn cache_fold_preserves_key_tags_and_counts_missing_removes_by_authority() {
    let limits = Limits::default();
    let mutations = vec![
        store_at(
            integer_hash(1),
            CacheGroup::Unspecified,
            StorageMedium::Unspecified,
        ),
        store_at(
            integer_hash(1),
            CacheGroup::Index { value: 0 },
            StorageMedium::Unspecified,
        ),
        store_at(
            integer_hash(1),
            CacheGroup::Unspecified,
            StorageMedium::Named {
                value: "GPU".to_owned(),
            },
        ),
        store_at(
            OpaqueHash::Bytes {
                value: Base64Bytes::new(vec![1]),
            },
            CacheGroup::Unspecified,
            StorageMedium::Unspecified,
        ),
        store(1),
        remove(99),
    ];
    let mut exact_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let exact_delivery = prepare(&mut exact_normalizer, "keys", 0, mutations.clone());
    let mut exact = trusted_state(&mut exact_normalizer, 0);
    exact.admit(exact_delivery).unwrap();
    assert_eq!(exact.cache_view().key_count(), 4);
    assert_eq!(exact.diagnostics().missing_removes_exact(), 1);

    let mut partial_normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let partial_delivery = prepare(&mut partial_normalizer, "keys", 0, mutations);
    let mut partial = unknown_state(&mut partial_normalizer, 0);
    partial.admit(partial_delivery).unwrap();
    assert_eq!(partial.cache_view().key_count(), 4);
    assert_eq!(partial.diagnostics().missing_removes_partial(), 1);
}

#[test]
fn cache_view_limits_fail_atomically_and_poison_further_use() {
    let limits = Limits {
        max_cache_keys_per_stream: 1,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let delivery = prepare(&mut normalizer, "too-many", 0, vec![store_many(&[1, 2])]);
    let mut state = trusted_state(&mut normalizer, 0);

    assert_eq!(
        state.admit(delivery),
        Err(Error::ResourceLimit {
            resource: Resource::CacheKeys,
            maximum: 1,
            observed: 2,
        })
    );
    assert_eq!(state.cache_view().key_count(), 0);
    assert_eq!(state.frontier(), None);

    let another = prepare(&mut normalizer, "another", 0, vec![store(1)]);
    assert_eq!(state.admit(another), Err(Error::StateFailed));
}

#[test]
fn multi_envelope_cache_projection_rolls_back_every_state_component() {
    let limits = Limits {
        max_cache_keys_per_stream: 3,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let zero = prepare(&mut normalizer, "zero", 0, vec![store(0)]);
    let one = prepare(&mut normalizer, "one", 1, vec![store(1)]);
    let retry_one = Arc::clone(&one);
    let two = prepare(&mut normalizer, "two", 2, vec![store(2)]);
    let three = prepare(&mut normalizer, "three", 3, vec![store(3)]);
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(zero).unwrap();
    state.admit(two).unwrap();
    state.admit(three).unwrap();
    let pending_bytes = state.pending_canonical_bytes();
    let diagnostics = state.diagnostics();
    assert_eq!(state.pending_envelopes(), 2);
    assert_eq!(state.certainty(), Certainty::Recovering);

    assert_eq!(
        state.admit(one),
        Err(Error::ResourceLimit {
            resource: Resource::CacheKeys,
            maximum: 3,
            observed: 4,
        })
    );
    assert_eq!(state.frontier(), Some(0));
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.pending_envelopes(), 2);
    assert_eq!(state.pending_canonical_bytes(), pending_bytes);
    assert_eq!(state.certainty(), Certainty::Recovering);
    assert_eq!(state.diagnostics(), diagnostics);
    assert_eq!(state.admit(retry_one), Err(Error::StateFailed));
}

#[test]
fn failing_barrier_projection_cannot_clear_prior_view_or_conflict_state() {
    let limits = Limits {
        max_cache_keys_per_stream: 2,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let zero = prepare(&mut normalizer, "zero", 0, vec![store(0)]);
    let three_a = prepare(&mut normalizer, "three-a", 3, vec![store(3)]);
    let three_b = prepare(&mut normalizer, "three-b", 3, vec![store(30)]);
    let barrier = prepare(
        &mut normalizer,
        "barrier",
        2,
        vec![clear(), store_many(&[1, 2, 3])],
    );
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(zero).unwrap();
    state.admit(three_a).unwrap();
    state.admit(three_b).unwrap();
    let diagnostics = state.diagnostics();
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert_eq!(state.pending_envelopes(), 1);
    assert_eq!(state.recent_fingerprints(), 1);

    assert_eq!(
        state.admit(barrier),
        Err(Error::ResourceLimit {
            resource: Resource::CacheKeys,
            maximum: 2,
            observed: 3,
        })
    );
    assert_eq!(state.frontier(), Some(0));
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.pending_envelopes(), 1);
    assert_eq!(state.pending_canonical_bytes(), 0);
    assert_eq!(state.recent_fingerprints(), 1);
    assert_eq!(state.certainty(), Certainty::Unknown);
    assert!(state.view_authoritative());
    assert_eq!(state.diagnostics(), diagnostics);
}

#[test]
fn opaque_cache_view_equality_includes_the_canonical_stream_scope() {
    let mut normalizer = EnvelopeNormalizer::new(Limits::default()).unwrap();
    let first = StreamState::new(
        &declaration_for("stream-a", "instance-a", Baseline::EmptyAtEngineStart, 0),
        BaselineAuthority::TrustDeclaredEmpty,
        &mut normalizer,
    )
    .unwrap();
    let second = StreamState::new(
        &declaration_for("stream-b", "instance-b", Baseline::EmptyAtEngineStart, 0),
        BaselineAuthority::TrustDeclaredEmpty,
        &mut normalizer,
    )
    .unwrap();

    assert!(first.cache_view() != second.cache_view());
}

#[test]
fn session_registration_binds_stream_id_scope_cursor_and_baseline() {
    let limits = Limits::default();

    let mut identical = EnvelopeNormalizer::new(limits).unwrap();
    let first = trusted_state(&mut identical, 0);
    let second = trusted_state(&mut identical, 0);
    assert!(first.cache_view() == second.cache_view());

    let mut changed_cursor = EnvelopeNormalizer::new(limits).unwrap();
    trusted_state(&mut changed_cursor, 0);
    assert_eq!(
        StreamState::new(
            &declaration(Baseline::EmptyAtEngineStart, 1),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut changed_cursor,
        )
        .err(),
        Some(Error::ConflictingStreamRegistration)
    );
    assert_eq!(
        changed_cursor
            .prepare(validated(Record::Envelope(raw_envelope(
                "after-registration-failure",
                "stream-a",
                0,
                Origin::Live,
                Vec::new(),
            ))))
            .err(),
        Some(Error::NormalizerFailed)
    );
    assert!(matches!(
        changed_cursor.seal(),
        Err(Error::NormalizerFailed)
    ));

    let mut changed_baseline = EnvelopeNormalizer::new(limits).unwrap();
    trusted_state(&mut changed_baseline, 0);
    assert_eq!(
        StreamState::new(
            &declaration(Baseline::UnknownAtAttach, 0),
            BaselineAuthority::TreatAsUnknown,
            &mut changed_baseline,
        )
        .err(),
        Some(Error::ConflictingStreamRegistration)
    );

    let mut changed_authority = EnvelopeNormalizer::new(limits).unwrap();
    trusted_state(&mut changed_authority, 0);
    assert_eq!(
        StreamState::new(
            &declaration(Baseline::EmptyAtEngineStart, 0),
            BaselineAuthority::TreatAsUnknown,
            &mut changed_authority,
        )
        .err(),
        Some(Error::ConflictingStreamRegistration)
    );

    let mut changed_scope = EnvelopeNormalizer::new(limits).unwrap();
    trusted_state(&mut changed_scope, 0);
    assert_eq!(
        StreamState::new(
            &declaration_for(
                "stream-a",
                "other-instance",
                Baseline::EmptyAtEngineStart,
                0,
            ),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut changed_scope,
        )
        .err(),
        Some(Error::ConflictingStreamRegistration)
    );

    let mut duplicate_scope = EnvelopeNormalizer::new(limits).unwrap();
    trusted_state(&mut duplicate_scope, 0);
    assert_eq!(
        StreamState::new(
            &declaration_for("stream-b", "instance", Baseline::EmptyAtEngineStart, 0,),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut duplicate_scope,
        )
        .err(),
        Some(Error::DuplicateStreamScope)
    );
}

#[test]
fn session_registration_limits_accept_n_and_reject_n_plus_one() {
    const IDENTITY_BYTES: u64 = 37;

    let no_streams = Limits {
        max_streams_per_trace: 0,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(no_streams).unwrap();
    assert!(matches!(
        StreamState::new(
            &declaration(Baseline::EmptyAtEngineStart, 0),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut normalizer,
        ),
        Err(Error::ResourceLimit {
            resource: Resource::SessionStreams,
            maximum: 0,
            observed: 1,
        })
    ));

    let exact = Limits {
        max_identity_bytes_per_trace: IDENTITY_BYTES,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(exact).unwrap();
    trusted_state(&mut normalizer, 0);

    let below = Limits {
        max_identity_bytes_per_trace: IDENTITY_BYTES - 1,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(below).unwrap();
    assert!(matches!(
        StreamState::new(
            &declaration(Baseline::EmptyAtEngineStart, 0),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut normalizer,
        ),
        Err(Error::ResourceLimit {
            resource: Resource::SessionIdentityBytes,
            maximum,
            observed,
        }) if maximum == IDENTITY_BYTES - 1 && observed == IDENTITY_BYTES
    ));
}

#[test]
fn cache_identity_byte_limit_accepts_n_and_rejects_n_plus_one_atomically() {
    let limits = Limits {
        max_cache_identity_bytes_per_stream: 2,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let at_limit = prepare(
        &mut normalizer,
        "at-limit",
        0,
        vec![store_at(
            OpaqueHash::Bytes {
                value: Base64Bytes::new(vec![1, 2]),
            },
            CacheGroup::Unspecified,
            StorageMedium::Unspecified,
        )],
    );
    let above_limit = prepare(
        &mut normalizer,
        "above-limit",
        1,
        vec![store_at(
            OpaqueHash::Bytes {
                value: Base64Bytes::new(vec![3]),
            },
            CacheGroup::Unspecified,
            StorageMedium::Unspecified,
        )],
    );
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(at_limit).unwrap();
    assert_eq!(state.cache_view().identity_bytes(), 2);
    assert_eq!(
        state.admit(above_limit),
        Err(Error::ResourceLimit {
            resource: Resource::CacheIdentityBytes,
            maximum: 2,
            observed: 3,
        })
    );
    assert_eq!(state.frontier(), Some(0));
    assert_eq!(state.cache_view().key_count(), 1);
    assert_eq!(state.cache_view().identity_bytes(), 2);
}

#[test]
fn remove_and_store_are_idempotent_at_the_modeled_membership_layer() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first = prepare(&mut normalizer, "first", 0, vec![store(1), store(1)]);
    let second = prepare(&mut normalizer, "second", 1, vec![remove(1)]);
    let third = prepare(&mut normalizer, "third", 2, vec![remove(1)]);
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(first).unwrap();
    assert_eq!(state.cache_view().key_count(), 1);
    state.admit(second).unwrap();
    assert_eq!(state.cache_view().key_count(), 0);
    state.admit(third).unwrap();
    assert_eq!(state.cache_view().key_count(), 0);
    assert_eq!(state.diagnostics().missing_removes_exact(), 1);
}

#[test]
fn normalizer_enforces_per_envelope_and_cumulative_hash_budgets_once() {
    let empty = raw_envelope("empty", "stream-a", 0, Origin::Live, Vec::new());
    let canonical = serde_json_canonicalizer::to_vec(&empty.mutations).unwrap();
    let cumulative = Limits {
        max_fingerprint_bytes_per_trace: u64::try_from(canonical.len()).unwrap(),
        ..Limits::default()
    };
    let mut cumulative_normalizer = EnvelopeNormalizer::new(cumulative).unwrap();
    let _first = cumulative_normalizer
        .prepare(validated(Record::Envelope(empty.clone())))
        .unwrap();
    assert_eq!(cumulative_normalizer.fingerprint_bytes(), 2);
    let error = cumulative_normalizer
        .prepare(validated(Record::Envelope(EventEnvelope {
            envelope_id: "second".to_owned(),
            ..empty.clone()
        })))
        .err()
        .unwrap();
    assert!(matches!(
        error,
        Error::ResourceLimit {
            resource: Resource::FingerprintBytes,
            maximum: 2,
            observed,
        } if observed > 2
    ));
    assert_eq!(
        cumulative_normalizer
            .prepare(validated(Record::Envelope(empty.clone())))
            .err(),
        Some(Error::NormalizerFailed)
    );

    let per_envelope = Limits {
        max_line_bytes: canonical.len() - 1,
        ..Limits::default()
    };
    let mut line_normalizer = EnvelopeNormalizer::new(per_envelope).unwrap();
    assert!(matches!(
        line_normalizer
            .prepare(validated(Record::Envelope(empty.clone())))
            .err(),
        Some(Error::ResourceLimit {
            resource: Resource::CanonicalMutationBytes,
            maximum,
            observed,
        }) if maximum == u64::try_from(canonical.len() - 1).unwrap() && observed > maximum
    ));

    let mut reusable_normalizer = EnvelopeNormalizer::new(Limits::default()).unwrap();
    let reusable = reusable_normalizer
        .prepare(validated(Record::Envelope(empty)))
        .unwrap();
    let mut state = trusted_state(&mut reusable_normalizer, 0);
    let bytes_before = reusable_normalizer.fingerprint_bytes();
    state.admit(Arc::clone(&reusable)).unwrap();
    state.admit(reusable).unwrap();
    assert_eq!(reusable_normalizer.fingerprint_bytes(), bytes_before);
}

#[test]
fn normalizer_bounds_and_uniquely_registers_retained_envelope_evidence() {
    let one_envelope = Limits {
        max_envelopes_per_trace: 1,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(one_envelope).unwrap();
    let retained = prepare_for(
        &mut normalizer,
        "first",
        "stream-a",
        0,
        Origin::Replay,
        Vec::new(),
    );
    assert_eq!(retained.envelope_id(), "first");
    assert_eq!(retained.origin(), Origin::Replay);
    assert!(matches!(
        normalizer
            .prepare(validated(Record::Envelope(raw_envelope(
                "second",
                "stream-a",
                1,
                Origin::Live,
                Vec::new(),
            ))))
            .err(),
        Some(Error::ResourceLimit {
            resource: Resource::SessionEnvelopes,
            maximum: 1,
            observed: 2,
        })
    ));

    let mut duplicate = EnvelopeNormalizer::new(Limits::default()).unwrap();
    prepare(&mut duplicate, "same", 0, Vec::new());
    assert_eq!(
        duplicate
            .prepare(validated(Record::Envelope(raw_envelope(
                "same",
                "stream-a",
                1,
                Origin::Replay,
                Vec::new(),
            ))))
            .err(),
        Some(Error::DuplicateEnvelopeRegistration)
    );

    let exact_identity = Limits {
        max_identity_bytes_per_trace: 1,
        ..Limits::default()
    };
    let mut exact = EnvelopeNormalizer::new(exact_identity).unwrap();
    prepare(&mut exact, "a", 0, Vec::new());

    let mut exceeded = EnvelopeNormalizer::new(exact_identity).unwrap();
    assert!(matches!(
        exceeded
            .prepare(validated(Record::Envelope(raw_envelope(
                "ab",
                "stream-a",
                0,
                Origin::Live,
                Vec::new(),
            ))))
            .err(),
        Some(Error::ResourceLimit {
            resource: Resource::SessionIdentityBytes,
            maximum: 1,
            observed: 2,
        })
    ));
}

#[test]
fn exact_summary_requires_the_matching_consumed_session_seal() {
    let limits = Limits {
        max_fingerprint_bytes_per_trace: 2,
        ..Limits::default()
    };
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let mut state = trusted_state(&mut normalizer, 0);
    let source = prepare(&mut normalizer, "only", 0, Vec::new());
    state.admit(source).unwrap();

    let sealed = normalizer.seal().unwrap();
    let summary = state.finish(&sealed).unwrap();
    assert_eq!(summary.certainty(), Certainty::Exact);
    assert!(summary.unknown_reasons().is_empty());

    let mut first_session = EnvelopeNormalizer::new(Limits::default()).unwrap();
    let first_state = trusted_state(&mut first_session, 0);
    let second_session = EnvelopeNormalizer::new(Limits::default()).unwrap();
    let wrong_seal = second_session.seal().unwrap();
    assert!(matches!(
        first_state.finish(&wrong_seal),
        Err(Error::SessionMismatch)
    ));
}

#[test]
fn active_limits_wrong_kinds_scope_and_cursor_defenses_are_fail_closed() {
    let invalid_depth = Limits {
        max_depth: MAX_JSON_DEPTH + 1,
        ..Limits::default()
    };
    assert_eq!(
        EnvelopeNormalizer::new(invalid_depth).err(),
        Some(Error::UnsupportedDepthLimit {
            configured: MAX_JSON_DEPTH + 1,
            maximum: MAX_JSON_DEPTH,
        })
    );
    let strict = Limits {
        max_identity_bytes: 2,
        ..Limits::default()
    };
    let mut strict_normalizer = EnvelopeNormalizer::new(strict).unwrap();
    assert_eq!(
        StreamState::new(
            &declaration(Baseline::EmptyAtEngineStart, 0),
            BaselineAuthority::TrustDeclaredEmpty,
            &mut strict_normalizer,
        )
        .err(),
        Some(Error::RecordValidation {
            error: ValidationError::FieldTooLong {
                field: "stream_id",
                limit: 2,
                actual: 8,
            },
        })
    );

    let limits = Limits::default();
    let mut wrong = EnvelopeNormalizer::new(limits).unwrap();
    assert_eq!(
        wrong
            .prepare(declaration(Baseline::EmptyAtEngineStart, 0))
            .err(),
        Some(Error::WrongRecordKind)
    );
    assert_eq!(
        wrong
            .prepare(validated(Record::Envelope(raw_envelope(
                "e",
                "stream-a",
                0,
                Origin::Live,
                Vec::new(),
            ))))
            .err(),
        Some(Error::NormalizerFailed)
    );

    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let other = prepare_for(
        &mut normalizer,
        "other",
        "stream-b",
        0,
        Origin::Live,
        Vec::new(),
    );
    let mut state = trusted_state(&mut normalizer, 0);
    assert_eq!(state.admit(other), Err(Error::StreamMismatch));

    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let below = prepare(&mut normalizer, "below", 0, Vec::new());
    let mut state = trusted_state(&mut normalizer, 1);
    assert_eq!(state.admit(below), Err(Error::CursorBeforeInitial));
}

#[test]
fn prepared_envelopes_are_bound_to_one_limits_and_fingerprint_session() {
    let limits = Limits::default();
    let mut source_session = EnvelopeNormalizer::new(limits).unwrap();
    let source = prepare(&mut source_session, "foreign", 0, vec![store(1)]);
    let mut state_session = EnvelopeNormalizer::new(limits).unwrap();
    let mut state = trusted_state(&mut state_session, 0);

    assert_eq!(
        state.admit(Arc::clone(&source)),
        Err(Error::SessionMismatch)
    );
    assert_eq!(state.frontier(), None);
    assert_eq!(state.admit(source), Err(Error::StateFailed));

    let strict = Limits {
        max_mutations_per_envelope: 1,
        ..limits
    };
    let mut strict_session = EnvelopeNormalizer::new(strict).unwrap();
    let mut state = trusted_state(&mut strict_session, 0);
    let too_many = prepare(
        &mut source_session,
        "foreign-profile",
        0,
        vec![store(1), store(2)],
    );
    assert_eq!(state.admit(too_many), Err(Error::SessionMismatch));

    let mut failed_session = EnvelopeNormalizer::new(limits).unwrap();
    let _state = trusted_state(&mut failed_session, 0);
    assert_eq!(
        failed_session
            .prepare(declaration(Baseline::EmptyAtEngineStart, 0))
            .err(),
        Some(Error::WrongRecordKind)
    );
    assert!(matches!(
        failed_session.seal(),
        Err(Error::NormalizerFailed)
    ));
}

#[test]
fn state_errors_have_stable_codes_and_never_echo_source_values() {
    const SECRET: &str = "ZXQ_STATE_SECRET_ID_77";

    let errors = [
        (
            Error::UnsupportedDepthLimit {
                configured: 65,
                maximum: 64,
            },
            "unsupported_depth_limit",
        ),
        (Error::NormalizerFailed, "normalizer_failed"),
        (Error::StateFailed, "state_failed"),
        (Error::SessionMismatch, "session_mismatch"),
        (
            Error::ConflictingStreamRegistration,
            "conflicting_stream_registration",
        ),
        (Error::DuplicateStreamScope, "duplicate_stream_scope"),
        (
            Error::DuplicateEnvelopeRegistration,
            "duplicate_envelope_registration",
        ),
        (Error::WrongRecordKind, "wrong_record_kind"),
        (
            Error::RecordValidation {
                error: ValidationError::EmptyField { field: "stream_id" },
            },
            "record_validation",
        ),
        (
            Error::FingerprintCanonicalization,
            "fingerprint_canonicalization",
        ),
        (
            Error::ResourceLimit {
                resource: Resource::CacheKeys,
                maximum: 0,
                observed: 1,
            },
            "state_resource_limit",
        ),
        (Error::CounterOverflow, "counter_overflow"),
        (
            Error::BaselineAuthorityMismatch,
            "baseline_authority_mismatch",
        ),
        (Error::StreamMismatch, "stream_mismatch"),
        (Error::CursorBeforeInitial, "cursor_before_initial"),
    ];
    for (error, code) in errors {
        assert_eq!(error.code(), code);
    }

    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let source = prepare_for(&mut normalizer, SECRET, SECRET, 0, Origin::Live, Vec::new());
    let mut state = trusted_state(&mut normalizer, 0);
    let error = state.admit(source).unwrap_err();
    assert!(!error.to_string().contains(SECRET));
    assert!(!format!("{error:?}").contains(SECRET));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bounded_delivery_sequences_are_deterministic_and_stay_bounded(
        events in prop::collection::vec((0_u8..12, any::<bool>()), 0..96)
    ) {
        let limits = Limits {
            max_recent_fingerprints_per_stream: 4,
            max_pending_envelopes_per_stream: 16,
            max_pending_canonical_bytes_per_stream: 64 * 1024,
            max_gap_span_per_stream: 16,
            max_cache_keys_per_stream: 32,
            ..Limits::default()
        };
        let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
        let mut first = trusted_state(&mut normalizer, 0);
        let mut second = trusted_state(&mut normalizer, 0);

        for (index, (cursor, variant)) in events.into_iter().enumerate() {
            let source = prepare(
                &mut normalizer,
                &format!("event-{index}"),
                u64::from(cursor),
                vec![store(u64::from(variant))],
            );
            let left = first.admit(Arc::clone(&source));
            let right = second.admit(source);
            prop_assert_eq!(left, right);
            prop_assert_eq!(first.certainty(), second.certainty());
            prop_assert_eq!(first.frontier(), second.frontier());
            prop_assert!(first.cache_view() == second.cache_view());
            prop_assert_eq!(first.diagnostics(), second.diagnostics());
            prop_assert!(first.pending_envelopes() <= limits.max_pending_envelopes_per_stream);
            prop_assert!(first.pending_canonical_bytes() <= limits.max_pending_canonical_bytes_per_stream);
            prop_assert!(first.recent_fingerprints() <= limits.max_recent_fingerprints_per_stream);
            prop_assert!(first.cache_view().key_count() <= limits.max_cache_keys_per_stream);
            if first.certainty() == Certainty::Exact {
                prop_assert!(first.view_authoritative());
                prop_assert_eq!(first.pending_envelopes(), 0);
            }
        }

        let sealed = normalizer.seal().unwrap();
        let left = first.finish(&sealed).unwrap();
        let right = second.finish(&sealed).unwrap();
        prop_assert_eq!(left.certainty(), right.certainty());
        prop_assert_eq!(left.frontier(), right.frontier());
        prop_assert!(left.cache_view() == right.cache_view());
        prop_assert_eq!(left.diagnostics(), right.diagnostics());
        prop_assert!(left.pending_envelopes() <= limits.max_pending_envelopes_per_stream);
        prop_assert!(left.recent_fingerprints() <= limits.max_recent_fingerprints_per_stream);
    }
}

#[test]
fn inert_extensions_never_change_payload_duplicate_classification() {
    let limits = Limits::default();
    let mut normalizer = EnvelopeNormalizer::new(limits).unwrap();
    let first = prepare(&mut normalizer, "first", 0, vec![store(1)]);
    let mut raw = raw_envelope("second", "stream-a", 0, Origin::Replay, vec![store(1)]);
    raw.extensions
        .insert("ignored".to_owned(), IrValue::String("value".to_owned()));
    let second = normalizer
        .prepare(validated(Record::Envelope(raw)))
        .unwrap();
    let mut state = trusted_state(&mut normalizer, 0);

    state.admit(first).unwrap();
    assert_eq!(state.admit(second).unwrap(), Disposition::Duplicate);
}
